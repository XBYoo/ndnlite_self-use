/*
 * Copyright (C) 2019 Xinyu Ma, Zhiyi Zhang
 *
 * 本文件遵循GNU Lesser General Public License v3.0的条款和条件。有关更多详细信息，请参见顶级目录中的LICENSE文件。
 *
 * 完整的NDN IOT PKG作者和贡献者列表请参见AUTHORS.md。
 */
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <ndn-lite.h>
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"

// 全局变量：端口1、端口2，服务器IP地址，名称前缀，运行状态
in_port_t port1, port2;
in_addr_t server_ip;
ndn_name_t name_prefix;
bool running;

// 解析命令行参数的函数
int parseArgs(int argc, char *argv[])
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
  // sz_prefix = argv[4]; // 可能用于名称前缀，暂时未使用
  // data_need = argv[5]; // 可能用于其他数据，暂时未使用

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
  server_ip = paddrs[0]->s_addr;

  // 解析本地端口号
  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port1 = htons((uint16_t) ul_port);

  // 解析远程端口号
  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port2 = htons((uint16_t) ul_port);

  // 解析名称前缀
  if(ndn_name_from_string(&name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  return 0;
}

// 处理接收到的数据的回调函数
void on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  printf("On data\n");
  // 解码数据并验证摘要
  if (ndn_data_tlv_decode_digest_verify(&data, rawdata, data_size)) {
    printf("Decoding failed.\n");
  }
  // 输出数据内容
  printf("It says: %s\n", data.content_value);
  running = false; // 停止运行
}

// 处理超时的回调函数
void on_timeout(void* userdata) {
  printf("On timeout\n");
  running = false; // 停止运行
}

// 主函数
int main(int argc, char *argv[])
{
  ndn_udp_face_t *face;
  ndn_interest_t interest;
  int ret;

  // 解析命令行参数
  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  // 启动ndn-lite
  ndn_lite_startup();

  // 创建UDP单播接口
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip, port2);

  // 添加路由
  ndn_forwarder_add_route_by_name(&face->intf, &name_prefix);

  // 根据名称前缀创建兴趣包
  ndn_interest_from_name(&interest, &name_prefix);

  // 发送兴趣包并设置回调函数
  ndn_forwarder_express_interest_struct(&interest, on_data, on_timeout, NULL);

  running = true;
  while(running) {
    // 处理NDN转发器事件
    ndn_forwarder_process();
    usleep(10000); // 休眠10毫秒
  }

  // 销毁接口
  ndn_face_destroy(&face->intf);
  return 0;
}
