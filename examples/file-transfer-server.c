/*
 * Copyright (C) 2019 Yiran Lei
 *
 * 本文件受GNU Lesser General Public License v3.0条款的约束。
 * 参阅顶层目录中的LICENSE文件以获取更多详细信息。
 *
 * 查看AUTHORS.md以获取完整的NDN IoT PKG作者和贡献者列表。
 */

/*
 * 本文件实现了一个文件传输服务器，配合文件传输客户端使用。
 * 启动file-transfer-server，输入本地端口、客户端IP、客户端端口和名称。
 * 启动file-transfer-client，输入本地端口、服务器IP、服务器端口、名称和文件名。
 * 服务器会返回客户端请求的文件（如果文件存在于服务器目录中）。
 */

#include <stdio.h>                 // 标准输入输出库
#include <netdb.h>                 // 提供网络相关功能
#include <unistd.h>                // 提供UNIX标准库函数，如sleep等
#include <stdlib.h>                // 提供通用函数库，如内存分配
#include <ndn-lite.h>              // NDN-Lite库，处理NDN协议相关功能
#include "ndn-lite/encode/name.h"  // NDN-Lite库中用于编码/解码NDN名字的功能
#include "ndn-lite/encode/data.h"  // NDN-Lite库中用于编码/解码NDN数据包的功能
#include "ndn-lite/encode/interest.h" // NDN-Lite库中用于编码/解码NDN兴趣包的功能
#include "ndn-lite/app-support/ndn-sig-verifier.h" // 用于NDN签名验证的库

#define CHUNK_SIZE      1024//分片大小
#define CHUNK_SIZE_TLV  4096//TLV编码预留大小

// 使用的椭圆曲线私钥（硬编码） 
uint8_t secp256r1_prv_key_str[32] = {
0xA7, 0x58, 0x4C, 0xAB, 0xD3, 0x82, 0x82, 0x5B, 0x38, 0x9F, 0xA5, 0x45, 0x73, 0x00, 0x0A, 0x32,
0x42, 0x7C, 0x12, 0x2F, 0x42, 0x4D, 0xB2, 0xAD, 0x49, 0x8C, 0x8D, 0xBF, 0x80, 0xC9, 0x36, 0xB5
};

// 使用的椭圆曲线公钥（硬编码）
uint8_t secp256r1_pub_key_str[64] = {
0x99, 0x26, 0xD6, 0xCE, 0xF8, 0x39, 0x0A, 0x05, 0xD1, 0x8C, 0x10, 0xAE, 0xEF, 0x3C, 0x2A, 0x3C,
0x56, 0x06, 0xC4, 0x46, 0x0C, 0xE9, 0xE5, 0xE7, 0xE6, 0x04, 0x26, 0x43, 0x13, 0x8A, 0x3E, 0xD4,
0x6E, 0xBE, 0x0F, 0xD2, 0xA2, 0x05, 0x0F, 0x00, 0xAC, 0x6F, 0x5D, 0x4B, 0x29, 0x77, 0x2D, 0x54,
0x32, 0x27, 0xDC, 0x05, 0x77, 0xA7, 0xDC, 0xE0, 0xA2, 0x69, 0xC8, 0x8B, 0x4C, 0xBF, 0x25, 0xF2
};

// 全局变量定义，保存服务器和客户端的端口、IP等信息
in_port_t port1, port2;
in_addr_t client_ip;
ndn_name_t name_prefix;  // NDN中的名字前缀
uint8_t buf[4096];       // 缓冲区
uint8_t anchor_bytes[2048]; // 用于存储签名的缓冲区
uint32_t anchor_bytes_size;  // 签名字节大小
ndn_udp_face_t *face;     // UDP网络接口
bool running;             // 标志位，用于控制主循环

// 参数解析函数，解析命令行传入的参数
int parseArgs(int argc, char *argv[]){
  char *sz_port1, *sz_port2, *sz_addr;
  uint32_t ul_port;
  struct hostent * host_addr;
  struct in_addr ** paddrs;

  // 检查参数是否足够
  if(argc < 5){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <client-ip> <client-port> <name-prefix>\n");
    return 1;
  }
  // 提取参数
  sz_port1 = argv[1];
  sz_addr = argv[2];
  sz_port2 = argv[3];
  //sz_prefix = argv[4];
  //data_need = argv[5];
  // 检查参数是否为空
  if(strlen(sz_port1) <= 0 || strlen(sz_addr) <= 0 || strlen(sz_port2) <= 0){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }

  // 解析客户端IP地址
  host_addr = gethostbyname(sz_addr);
  if(host_addr == NULL){
    fprintf(stderr, "ERROR: wrong hostname.\n");
    return 2;
  }

  paddrs = (struct in_addr **)host_addr->h_addr_list;
  if(paddrs[0] == NULL){
    fprintf(stderr, "ERROR: wrong hostname.\n");
    return 2;
  }
  client_ip = paddrs[0]->s_addr;

  // 解析本地端口号
  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port1 = htons((uint16_t) ul_port);  // 将端口号转为网络字节序

  // 解析客户端端口号
  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port2 = htons((uint16_t) ul_port);

  // 解析名字前缀
  if(ndn_name_from_string(&name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }
  return 0;
}


// 调试日志
  void debug_interest_params(const ndn_interest_t* interest, const char* location){
    printf("DEBUG[%s]: parameters.size = %d\n", location, interest->parameters.size);
    printf("DEBUG[%s]: parameters.value = ", location);
    for(int i = 0; i < interest->parameters.size; i++) {
        printf("%02x ", interest->parameters.value[i]);
    }
    printf("\n");
}

// 当验证兴趣包成功时调用的回调函数
void
on_success(ndn_interest_t* interest, void* userdata)
{
  printf("verify succeed");
  char* file_name = interest->parameters.value; // 文件名
  int param_size = interest->parameters.size;   // 文件名大小
  file_name[param_size] = '\0';  // 确保文件名以空字符结尾

  unsigned char temp_buffer[CHUNK_SIZE];        // 分片缓存
  //FILE *fp = fopen(file_name,"r");
  FILE *fp = fopen(file_name, "rb");
  printf("The requested file name is: %s\nlength is %d\n",file_name,param_size);
  if(fp == NULL){
    fprintf(stderr, "ERROR: fail to open file.\n");
    return;
  }
  // 从文件中读取内容
  #if 0
  if(fgets(temp_buffer,1024,fp) == NULL){
    fprintf(stderr, "ERROR: fail to read file.\n");
    return;
  }
  // 将数据封装为NDN数据包，并对文件内容进行编码
  tlv_make_data(data_buf,4096,&data_off,
  3,TLV_DATAARG_NAME_PTR,&interest->name,
  TLV_DATAARG_CONTENT_BUF,(uint8_t*)temp_buffer,TLV_DATAARG_CONTENT_SIZE,strlen(temp_buffer));//data_buf为TLV编码后数据
  // 通过NDN转发器发送数据包
  ndn_forwarder_put_data(data_buf,data_off);
  return;
  #else
  // 获取文件大小
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    printf("File size: %ld bytes\n", file_size);
    long file_size_remaining = file_size;
    uint8_t data_buf[CHUNK_SIZE_TLV];
    size_t data_off;
    uint64_t part_number = 0;  // 分片编号
    int arg = 0;
    while (file_size_remaining > 0) {
        // 计算每次读取的大小
        size_t bytes_to_read = (file_size_remaining < CHUNK_SIZE) ? file_size_remaining : CHUNK_SIZE;
        size_t bytes_read = fread(temp_buffer, 1, bytes_to_read, fp);
        
        if (bytes_read == 0) {
            break;
        }
        //uint64_t part_number = (file_size_remaining < CHUNK_SIZE) ? (uint64_t)-1 : part_number;
        tlv_make_data(data_buf,CHUNK_SIZE_TLV,&data_off,  // 将数据封装为NDN数据包，并对文件内容进行编码,data_buf为TLV编码后数据
        6,TLV_DATAARG_NAME_PTR,&interest->name
        ,TLV_DATAARG_CONTENT_BUF,(uint8_t*)temp_buffer
        ,TLV_DATAARG_CONTENT_SIZE,bytes_to_read
        ,TLV_DATAARG_NAME_SEGNO_U64,part_number
        ,TLV_DATAARG_FINALBLOCKID_U64,(uint64_t)(file_size/CHUNK_SIZE)
        ,TLV_DATAARG_FRESHNESSPERIOD_U64, (uint64_t)1500);  // 设置1.5秒的新鲜度期
        ndn_forwarder_put_data(data_buf,data_off); // 通过NDN转发器发送数据包
        // 更新剩余文件大小
        file_size_remaining -= bytes_read;
        part_number++;
        printf("circulation: part_number = %d \n", part_number);
    }

  #endif
  return;
  debug_interest_params(interest, "on_forwarder");
}

// 当验证兴趣包失败时调用的回调函数
void
on_failure(ndn_interest_t* interest, void* userdata)
{
  printf("Cannot verify");
}



// 定义回调函数指针，成功和失败时分别调用相应的处理函数
void (* p_on_success)(ndn_interest_t*, void*) = &on_success;  // &可以省略
void (* p_on_failure)(ndn_interest_t*, void*) = &on_failure;  // &可以省略

// 处理兴趣包的函数
int on_interest(const uint8_t* interest, uint32_t interest_size, void* userdata) {
  ndn_data_t data;  // 用于存储生成的数据包
  ndn_encoder_t encoder;  // 编码器，用于编码数据包

  printf("On interest\n");  // 输出兴趣包接收的提示信息
  // 验证兴趣包的签名。验证通过调用成功回调，失败则调用失败回调
  ndn_sig_verifier_verify_int(interest, interest_size, p_on_success, NULL, p_on_failure, NULL);
}

// 主函数
int main(int argc, char *argv[]){
  int ret;
  ndn_encoder_t encoder;  // 编码器，用于后续编码操作

  // 解析命令行参数
  if ((ret = parseArgs(argc, argv)) != 0) {
    return ret;
  }

  // 启动NDN-Lite库
  ndn_lite_startup();

  // 创建UDP单播Face接口，用于通信
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, client_ip, port2);

  // 模拟引导过程，初始化锚点私钥和公钥
  ndn_ecc_prv_t anchor_prv_key;  // 锚点私钥
  ndn_ecc_prv_init(&anchor_prv_key, secp256r1_prv_key_str, sizeof(secp256r1_prv_key_str), NDN_ECDSA_CURVE_SECP256R1, 123);

  ndn_ecc_pub_t anchor_pub_key;  // 锚点公钥
  ndn_ecc_pub_init(&anchor_pub_key, secp256r1_pub_key_str, sizeof(secp256r1_pub_key_str), NDN_ECDSA_CURVE_SECP256R1, 123);
  printf("1\n"); 
  // 测试生成的密钥对
  #if 0
  ndn_ecc_make_key(&anchor_pub_key, &anchor_prv_key, NDN_ECDSA_CURVE_SECP256R1, 123);
  uint8_t* starting = ndn_ecc_get_pub_key_value(&anchor_pub_key);
  for (int i = 0; i < ndn_ecc_get_pub_key_size(&anchor_pub_key); i++) {
    fprintf(stdout, "0x%02X%s", 
    *(starting + i), ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
  }
  printf("\n\n");
  starting = &anchor_prv_key.abs_key.key_value;
  for (int i = 0; i < ndn_ecc_get_prv_key_size(&anchor_prv_key); i++) {
      fprintf(stdout, "0x%02X%s",
     *(starting + i),
     ( i + 1 ) % 16 == 0 ? "\r\n" : " " );
  }
  #endif
  // 这段代码打印公钥和私钥的值，检查密钥对是否生成正确

  // 初始化锚点数据包
  ndn_data_t anchor;
  ndn_data_init(&anchor);  // 初始化数据包
  ndn_name_from_string(&anchor.name, "/ndn-iot/controller/KEY", strlen("/ndn-iot/controller/KEY"));  // 设置数据包名字
  ndn_name_t anchor_id;
  memcpy(&anchor_id, &anchor.name, sizeof(ndn_name_t));  // 复制名字到anchor_id
  anchor_id.components_size -= 1;  // 去掉最后一个组件，用于签名操作
  ndn_name_append_keyid(&anchor.name, 123);  // 添加密钥ID组件
  ndn_name_append_string_component(&anchor.name, "self", strlen("self"));  // 添加自定义字符串组件
  ndn_name_append_keyid(&anchor.name, 456);  // 再次添加密钥ID组件
 printf("2\n"); 
  // 设置数据内容为锚点的公钥
  ndn_data_set_content(&anchor, secp256r1_pub_key_str, sizeof(secp256r1_pub_key_str));

  // 对数据包进行编码并签名
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &anchor, &anchor_id, &anchor_prv_key);
  anchor_bytes_size = encoder.offset;  // 保存编码后的字节大小
 printf("3\n"); 
  // 解码数据包，不进行验证
  ndn_data_tlv_decode_no_verify(&anchor, encoder.output_value, encoder.offset, NULL, NULL);
 printf("4\n"); 

  // 将锚点数据存入密钥存储，作为信任锚点
  ndn_key_storage_set_trust_anchor(&anchor);
  // 生成新的密钥对
  ndn_ecc_pub_t* self_pub = NULL;
  ndn_ecc_prv_t* self_prv = NULL;
  ndn_key_storage_get_empty_ecc_key(&self_pub, &self_prv);  // 获取空的ECC密钥位置
  ndn_ecc_make_key(self_pub, self_prv, NDN_ECDSA_CURVE_SECP256R1, 234);  // 生成密钥对

  // 初始化自证书
  ndn_data_t self_cert;
  ndn_data_init(&self_cert);  // 初始化数据包
  ndn_name_from_string(&self_cert.name, "/ndn-iot/bedroom/file-server/KEY", strlen("/ndn-iot/bedroom/file-server/KEY"));  // 设置名字
  ndn_name_append_keyid(&self_cert.name, 234);  // 添加密钥ID组件
  ndn_name_append_string_component(&self_cert.name, "home", strlen("home"));  // 添加自定义字符串组件
  ndn_name_append_keyid(&self_cert.name, 567);  // 再次添加密钥ID组件

  // 设置自证书的内容为自身的公钥
  ndn_data_set_content(&self_cert, ndn_ecc_get_pub_key_value(self_pub), ndn_ecc_get_pub_key_size(self_pub));

  // 对自证书进行编码并签名
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &self_cert, &anchor_id, &anchor_prv_key);

  // 解码自证书，不进行验证
  ndn_data_tlv_decode_no_verify(&self_cert, encoder.output_value, encoder.offset, NULL, NULL);

  // 将自证书和私钥存入密钥存储
  ndn_key_storage_set_self_identity(&self_cert, self_prv);

  // 设置签名验证器
  ndn_sig_verifier_after_bootstrapping(&face->intf);

  running = true;

  // 编码名字前缀
  encoder_init(&encoder, buf, sizeof(buf));
  ndn_name_tlv_encode(&encoder, &name_prefix);

  // 注册名字前缀，并指定处理兴趣包的回调函数
  ndn_forwarder_register_prefix(encoder.output_value, encoder.offset, on_interest, NULL);

  // 进入事件循环，处理收到的兴趣包
  while (running) {

    ndn_forwarder_process();  // 处理转发器中的事件
    usleep(10000);  // 休眠10毫秒，防止占用过多CPU
  }

  // 退出事件循环后销毁Face接口，释放资源
  ndn_face_destroy(&face->intf);

  return 0;
}
