#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <ndn-lite.h>
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"

// 全局变量
in_port_t port1, port2, port3, port4;
in_addr_t server_ip1, server_ip2;
ndn_name_t name_prefix1, name_prefix2;
uint8_t buf[4096];          // 数据缓存区，用于存放编码后的数据包
bool running;

// 解析命令行参数
int parseArgs(int argc, char *argv[], in_port_t *port1, in_port_t *port2, in_addr_t *server_ip, ndn_name_t *name_prefix)
{
  char *sz_port1, *sz_port2, *sz_addr;
  uint32_t ul_port;
  struct hostent * host_addr;
  struct in_addr ** paddrs;

  // 检查命令行参数数量
  if(argc < 5) {
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <remote-ip> <remote-port> <name-prefix>\n");
    return 1;
  }
  sz_port1 = argv[1];
  sz_addr = argv[2];
  sz_port2 = argv[3];

  // 检查参数是否为空
  if(strlen(sz_port1) <= 0 || strlen(sz_addr) <= 0 || strlen(sz_port2) <= 0){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }

  // 获取主机名对应的IP地址
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
  *server_ip = paddrs[0]->s_addr;

  // 解析本地端口号
  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  *port1 = htons((uint16_t) ul_port);

  // 解析远程端口号
  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  *port2 = htons((uint16_t) ul_port);

  // 解析名称前缀
  if(ndn_name_from_string(name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  return 0;
}
// 收到兴趣包
int on_interest(const uint8_t* interest, uint32_t interest_size, void* userdata)
{
  ndn_data_t data;  // 定义NDN数据包结构体
  ndn_encoder_t encoder;  // 定义编码器
  char * str = "I'm a Data packet.";  // 数据包内容

  printf("On interest\n");
  data.name = name_prefix1;  // 使用全局的名字前缀
  
  ndn_data_set_content(&data, (uint8_t*)str, strlen(str) + 1);  // 附带/0 +1

  ndn_metainfo_init(&data.metainfo);  // 初始化元信息
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);  // 设置数据包类型
  encoder_init(&encoder, buf, 4096);  // 初始化编码器
  ndn_data_tlv_encode_digest_sign(&encoder, &data);  // 对数据包进行TLV编码并签名
  ndn_forwarder_put_data(encoder.output_value, encoder.offset);  // 将数据包发送到转发器

  return NDN_FWD_STRATEGY_SUPPRESS;  // 抑制策略，用于控制NDN的转发策略
}
// 收到数据包
void on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  printf("中继节点数据包收到\n");
  // 解码数据并验证摘要
  if (ndn_data_tlv_decode_digest_verify(&data, rawdata, data_size)) {
    printf("解码失败.\n");
  }
  // 输出数据内容
  printf("收到数据内容: %s\n", data.content_value);
  running = false; // 停止运行
}

void on_timeout(void* userdata) {
  printf("超时\n");
  running = false; // 停止运行
}
int main(int argc, char *argv[])
{
  ndn_udp_face_t *face1;//consumer
  ndn_udp_face_t *face2;//producer
  int ret;
  ndn_interest_t *interest;
  ndn_data_t *data;
  ndn_name_t interest_name;

  // 检查命令行参数数量
  if(argc < 9) {
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port1> <remote-ip1> <remote-port1> <name-prefix1> <local-port2> <remote-ip2> <remote-port2> <name-prefix2>\n");
    return 1;
  }
// for test name_prefix1 == name_prefix2
  // 解析第一组命令行参数
  if((ret = parseArgs(argc, argv, &port1, &port2, &server_ip1, &name_prefix1)) != 0){
    return ret;
  }
  // 解析第二组命令行参数
  if((ret = parseArgs(argc, argv + 4, &port3, &port4, &server_ip2, &name_prefix2)) != 0){
    return ret;
  }

  // 启动ndn-lite
  ndn_lite_startup();

  // 创建两个UDP单播接口
  face1 = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip1, port2);
  face2 = ndn_udp_unicast_face_construct(INADDR_ANY, port3, server_ip2, port4);
  // 添加路由
  ndn_forwarder_add_route_by_name(&face1->intf, &name_prefix1);
  ndn_forwarder_add_route_by_name(&face2->intf, &name_prefix2);

  ndn_forwarder_register_name_prefix(&name_prefix1, on_interest, NULL);//收录生产者节点兴趣包
  // 根据名称前缀创建兴趣包
  ndn_interest_from_name(&interest, &name_prefix2);
  // 发送兴趣包并设置回调函数
  ndn_forwarder_express_interest_struct(&interest, on_data, on_timeout, NULL);

  running = true;
  while(running) {

// 处理NDN转发器事件
    ndn_forwarder_process();//负责处理转发器中的事件队列，定期轮询转发器内的事件队列，包括接收、处理和转发兴趣包或数据包。
    usleep(10000); // 10毫秒
  }

  // 销毁接口
  ndn_face_destroy(&face1->intf);
  ndn_face_destroy(&face2->intf);
  return 0;
}
