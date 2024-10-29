/*
 * Copyright (C) 2019 Yiran Lei
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v3.0. See the file LICENSE in the top level
 * directory for more details.
 *
 * See AUTHORS.md for complete list of NDN IOT PKG authors and contributors.
 */
/*
 * This file-tranfer-client works with file-transfer-server.
 * Launch the file-transfer-server, input local port, client ip, client port and name.
 * Launch the file-transfer-client, input local port, server ip, server port, name and the file name.
 * The server will then return the requested file to the client. (if the file exists in the directory)
 */

#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <ndn-lite.h>
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/encode/signed-interest.h"
#include "ndn-lite/app-support/ndn-sig-verifier.h"
#include <termios.h>
#include <fcntl.h>
#include <stdbool.h>
#include <signal.h>


// 定义全局变量
in_port_t port1, port2;  // 本地和远程的端口号
in_addr_t server_ip;     // 服务器IP地址
char *file_name;         // 要请求的文件名
ndn_name_t name_prefix;  // NDN的名字前缀
uint8_t buf[4096];       // 存储数据的缓冲区
uint8_t anchor_bytes[2048];  // 锚数据缓冲区
uint32_t anchor_bytes_size;  // 锚数据大小
volatile bool running;            // 全局变量volatile 表示程序运行状态的标志



// secp256r1 密钥对（椭圆曲线ECDSA）
uint8_t secp256r1_prv_key_str[32] = {
0xA7, 0x58, 0x4C, 0xAB, 0xD3, 0x82, 0x82, 0x5B, 0x38, 0x9F, 0xA5, 0x45, 0x73, 0x00, 0x0A, 0x32,
0x42, 0x7C, 0x12, 0x2F, 0x42, 0x4D, 0xB2, 0xAD, 0x49, 0x8C, 0x8D, 0xBF, 0x80, 0xC9, 0x36, 0xB5
};
uint8_t secp256r1_pub_key_str[64] = {
0x99, 0x26, 0xD6, 0xCE, 0xF8, 0x39, 0x0A, 0x05, 0xD1, 0x8C, 0x10, 0xAE, 0xEF, 0x3C, 0x2A, 0x3C,
0x56, 0x06, 0xC4, 0x46, 0x0C, 0xE9, 0xE5, 0xE7, 0xE6, 0x04, 0x26, 0x43, 0x13, 0x8A, 0x3E, 0xD4,
0x6E, 0xBE, 0x0F, 0xD2, 0xA2, 0x05, 0x0F, 0x00, 0xAC, 0x6F, 0x5D, 0x4B, 0x29, 0x77, 0x2D, 0x54,
0x32, 0x27, 0xDC, 0x05, 0x77, 0xA7, 0xDC, 0xE0, 0xA2, 0x69, 0xC8, 0x8B, 0x4C, 0xBF, 0x25, 0xF2
};
// 解析命令行参数，初始化端口、IP地址、名字前缀和文件名
int parseArgs(int argc, char *argv[]){
  char *sz_port1, *sz_port2, *sz_addr;
  uint32_t ul_port;
  struct hostent * host_addr;
  struct in_addr ** paddrs;

  if(argc < 6){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <remote-ip> <remote-port> <name-prefix> <file-name>\n");
    return 1;
  }
  sz_port1 = argv[1];  // 本地端口
  sz_addr = argv[2];   // 服务端IP地址
  sz_port2 = argv[3];  // 服务端端口

  if(strlen(sz_port1) <= 0 || strlen(sz_addr) <= 0 || strlen(sz_port2) <= 0){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }
 // 解析服务器IP地址
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
  server_ip = paddrs[0]->s_addr;
  // 解析并验证端口号
  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port1 = htons((uint16_t) ul_port);

  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port2 = htons((uint16_t) ul_port);
// 初始化NDN名字前缀
  if(ndn_name_from_string(&name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  file_name = argv[5];// 要请求的文件名

  return 0;
}
// 保存文件函数，接收到的数据被保存到文件中
int save_file(uint8_t* file_data);

void on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata)
{
  printf("Receiving data\n");
  // 这里用于解析接收到的数据
  // char data_buf[1024];
  char* data_buf;
  int data_off;
 // 分配临时缓冲区来存储接收到的数据
  uint8_t* temp_buffer = malloc(data_size);
  memcpy(temp_buffer, rawdata, data_size);
 // 解析接收到的TLV数据
  //tlv_parse_data(rawdata,data_size,2,TLV_DATAARG_CONTENT_BUF,(uint8_t**)&data_buf,TLV_DATAARG_CONTENT_SIZE,&data_off);
  tlv_parse_data(temp_buffer,data_size,2,TLV_DATAARG_CONTENT_BUF,(uint8_t**)&data_buf,TLV_DATAARG_CONTENT_SIZE,&data_off);
 // 将解析后的数据保存到文件
  //printf("data\n%s\n",data_buf);
  save_file(data_buf);
   // 使用完后记得释放
   // 释放临时缓冲区
  free(temp_buffer);
}



// 保存文件的实现，将接收到的文件内容保存到本地
int
save_file(uint8_t* file_data)
{
  FILE * fp = fopen(file_name,"w");
  if(fp == NULL){
    fprintf(stderr, "ERROR: fail to open a file when writing.\n");
    return 1;
  }
  if(fputs((char*)file_data,fp) == EOF){
    fprintf(stderr, "ERROR: fail to write data.\n");
    return 1;
  }
  fclose(fp);
  return 0;
}

/*save_file(uint8_t* file_data)
{
FILE *fp = fopen(file_name, "rb"); // Open in binary mode
if (fp == NULL) {
    fprintf(stderr, "ERROR: fail to open file.\n");
    return;
}

size_t bytes_read = fread(temp_buffer, 1, sizeof(temp_buffer), fp);
if (bytes_read == 0) {
    fprintf(stderr, "ERROR: fail to read file or file is empty.\n");
    fclose(fp);
    return;
}
fclose(fp);

// Make sure data is properly terminated if used as a string
if (bytes_read < sizeof(temp_buffer)) {
    temp_buffer[bytes_read] = '\0';
}
}
*/

//volatile bool running = true;

// 信号处理函数
void signal_handler(int signum) {
    if (signum == SIGINT) {
      printf("收到Ctrl+C,程序将清理后退出n");
      //cleanup_resources();
        running = false;
    }
}

// 设置非阻塞输入
void set_nonblocking() {
    struct termios ttystate;
    tcgetattr(STDIN_FILENO, &ttystate);
    ttystate.c_lflag &= ~ICANON;
    ttystate.c_cc[VMIN] = 0;
    tcsetattr(STDIN_FILENO, TCSANOW, &ttystate);
    
    int flags = fcntl(STDIN_FILENO, F_GETFL);
    fcntl(STDIN_FILENO, F_SETFL, flags | O_NONBLOCK);
}


// 处理请求超时的回调函数
void on_timeout(void* userdata){
  printf("On file request interest timeout\n");
  running = false;
}

int main(int argc, char *argv[]){
  ndn_udp_face_t *face;
  ndn_encoder_t encoder;
  int ret;
 // 解析命令行参数
  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }
 // NDN-Lite 初始化
  ndn_lite_startup();

  // simulate bootstrapping process
  // 模拟引导过程，初始化锚点数据（签名和验证）
  ndn_ecc_prv_t anchor_prv_key;
  ndn_ecc_prv_init(&anchor_prv_key, secp256r1_prv_key_str, sizeof(secp256r1_prv_key_str),
                   NDN_ECDSA_CURVE_SECP256R1, 123);
  ndn_data_t anchor;
  ndn_data_init(&anchor);
  ndn_name_from_string(&anchor.name, "/ndn-iot/controller", strlen("/ndn-iot/controller"));
  ndn_name_t anchor_id;
  memcpy(&anchor_id, &anchor.name, sizeof(ndn_name_t));
  ndn_name_append_string_component(&anchor.name, "KEY", strlen("KEY"));
  ndn_name_append_keyid(&anchor.name, 123);
  ndn_name_append_string_component(&anchor.name, "self", strlen("self"));
  ndn_name_append_keyid(&anchor.name, 456);
  ndn_data_set_content(&anchor, secp256r1_pub_key_str, sizeof(secp256r1_pub_key_str));
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &anchor, &anchor_id, &anchor_prv_key);
  anchor_bytes_size = encoder.offset;
  ndn_data_tlv_decode_no_verify(&anchor, encoder.output_value, encoder.offset, NULL, NULL);
  ndn_key_storage_set_trust_anchor(&anchor);

  // ndn_ecc_prv_t self_prv_key
  ndn_ecc_pub_t* self_pub;
  ndn_ecc_prv_t* self_prv;
  ndn_key_storage_get_empty_ecc_key(&self_pub, &self_prv);
  ndn_ecc_make_key(self_pub, self_prv, NDN_ECDSA_CURVE_SECP256R1, 890);

  // self cert
  ndn_data_t self_cert;
  ndn_data_init(&self_cert);
  ndn_name_from_string(&self_cert.name, "/ndn-iot/bedroom/file-client/KEY", strlen("/ndn-iot/bedroom/file-client/KEY"));
  ndn_name_append_keyid(&self_cert.name, 890);
  ndn_name_append_string_component(&self_cert.name, "home", strlen("home"));
  ndn_name_append_keyid(&self_cert.name, 891);
  ndn_data_set_content(&self_cert, ndn_ecc_get_pub_key_value(self_pub),
                       ndn_ecc_get_pub_key_size(self_pub));
  encoder_init(&encoder, anchor_bytes, sizeof(anchor_bytes));
  ndn_data_tlv_encode_ecdsa_sign(&encoder, &self_cert, &anchor_id, &anchor_prv_key);
  ndn_data_tlv_decode_no_verify(&self_cert, encoder.output_value, encoder.offset, NULL, NULL);
  ndn_key_storage_set_self_identity(&self_cert, self_prv);

  // set up route
  // 初始化UDP面
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip, port2);
  
  // 准备要发送的兴趣包(Interest)
  running = true;
  // 初始化编码器，用于将NDN的名字或兴趣包等内容进行TLV编码。
// 使用`buf`作为编码的目标缓冲区，大小为4096字节。
  encoder_init(&encoder, buf, 4096);
  // 将NDN名字`name_prefix`进行TLV编码，准备后续发送兴趣包。
  ndn_name_tlv_encode(&encoder, &name_prefix);
  // set up sig verifier
  // 为转发器添加一条转发规则（路由）
  // 通过调用`ndn_forwarder_add_route`，我们在转发器中注册了一条路由规则，这条规则将Interest包根据名字前缀转发到指定的接口(face)。
  ndn_forwarder_add_route(&face->intf, buf, encoder.offset);
  // 启动签名验证器。它将在客户端启动后验证接收到的兴趣包和数据包的签名。

  // set up sig verifier
  ndn_sig_verifier_after_bootstrapping(&face->intf);
  // 初始化兴趣包(Interest)缓冲区，用来存储我们将要发送的兴趣包。
  char interest_buf[4096];
  // 获取密钥存储实例，通常用于保存本地的私钥和公钥信息。
  ndn_key_storage_t* storage = ndn_key_storage_get_instance();
  // 创建一个兴趣包`request`，使用之前编码好的名字`name_prefix`作为兴趣包的名字。
  ndn_interest_t request;
  ndn_interest_from_name(&request, &name_prefix);
  // 将文件名作为兴趣包的参数设置到请求中。
// Interest包的参数部分用于携带应用数据，这里我们将文件名作为参数传递。
  ndn_interest_set_Parameters(&request, (uint8_t*)file_name, strlen(file_name));
  // 设置Interest包的生命周期，单位为毫秒，10秒后如果未获取到响应则该兴趣包超时。
  request.lifetime = 10000;

  // 获取当前设备的身份密钥，适用ndn-lite的函数变更
  const ndn_name_t* identity = storage->self_identity;//new 20241021
  //ndn_signed_interest_ecdsa_sign(&request, &storage->self_identity, self_prv);
  // 使用ECDSA签名Interest包
  // `ndn_signed_interest_ecdsa_sign`函数会使用设备的私钥对兴趣包进行签名，确保该Interest包的来源可以被验证。
  ndn_signed_interest_ecdsa_sign(&request, identity, self_prv);
  // tlv_make_interest(interest_buf,4096,&interest_off,6,TLV_INTARG_NAME_PTR,&name_prefix,
  //                   TLV_INTARG_PARAMS_BUF,(uint8_t*)file_name,TLV_INTARG_PARAMS_SIZE,strlen(file_name),
  //                   TLV_INTARG_SIGTYPE_U8, NDN_SIG_TYPE_ECDSA_SHA256, TLV_INTARG_SIGKEY_PTR, self_prv,
  //                   TLV_INTARG_IDENTITYNAME_PTR, &storage->self_identity);
  // 初始化编码器以编码Interest包
// `encoder_init`用于初始化编码器，`interest_buf`为目标缓冲区，大小为4096字节。
  encoder_init(&encoder, interest_buf, 4096);
  // 使用编码器将Interest包编码为TLV格式。
  ndn_interest_tlv_encode(&encoder, &request);
  // 向NDN转发器发送Interest包
  // ndn_forwarder_express_interest`函数发送Interest包，
  // 同时注册两个回调函数：`on_data`用于处理接收到的数据包，`on_timeout`处理超时情况。
  ndn_forwarder_express_interest(interest_buf, encoder.offset, on_data, on_timeout, NULL);
    // 注册信号处理
    signal(SIGINT, signal_handler);//ctrl+c触发中断 阻塞的？(ctrl+c加回车信号中断)（程序中自带信号处理机制）
    //printf("Press 'q' to quit.\n");
    // 设置非阻塞输入
    //set_nonblocking();
    
    char c;
    while(running) {
        // 检查用户输入
        ndn_forwarder_process();
        usleep(10000);   
        // printf("Press 'q' to quit.\n");   
      /* if(read(STDIN_FILENO, &c, 1) > 0) {
            if(c == 'q') {
                running = false;
                continue;
            }
        }*/
    }
    printf("ndn_face_destroy.\n");
    ndn_face_destroy(&face->intf);
    return 0;
}

