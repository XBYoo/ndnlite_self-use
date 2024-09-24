/*
 * Copyright (C) 2019 Xinyu Ma, Zhiyi Zhang
 *
 * 本文件遵循GNU Lesser General Public License v3.0的条款和条件。更多详细信息请参见顶级目录中的LICENSE文件。
 *
 * 有关NDN IOT PKG作者和贡献者的完整列表，请参见AUTHORS.md。
 */
#include <stdio.h>
#include <netdb.h>
#include <unistd.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <ndn-lite.h>
#include "../adaptation/udp/udp-face.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"
#include "ndn-lite/encode/encoder.h"

// 全局变量定义：端口、组播IP、名称前缀、缓冲区、运行状态
in_port_t port;
in_addr_t multicast_ip;
ndn_name_t name_prefix;
uint8_t buf[4096];
bool running;

// 解析命令行参数的函数
int
parseArgs(int argc, char *argv[])
{
  char *sz_port, *sz_addr;
  uint32_t ul_port;

  // 检查参数数量是否足够
  if (argc < 2) {
    fprintf(stderr, "ERROR: 参数错误。\n");
    printf("Usage: <name-prefix> <port>=56363 <group-ip>=224.0.23.170\n");
    return 1;
  }

  // 将argv[1]转为NDN名称前缀
  if (ndn_name_from_string(&name_prefix, argv[1], strlen(argv[1])) != NDN_SUCCESS) {
    fprintf(stderr, "ERROR: 名称无效。\n");
    return 4;
  }

  // 设置默认端口和组播IP
  uint32_t portnum = 56363;
  port = htons(portnum);
  multicast_ip = inet_addr("224.0.23.170");

  // 如果提供了端口参数，进行解析
  if (argc >= 3) {
    sz_port = argv[2];
    if (strlen(sz_port) <= 0) {
      fprintf(stderr, "ERROR: 参数错误。\n");
      return 1;
    }
    ul_port = strtoul(sz_port, NULL, 10);
    if (ul_port < 1024 || ul_port >= 65536) {
      fprintf(stderr, "ERROR: 端口号无效。\n");
      return 3;
    }
    port = htons((uint16_t) ul_port);
  }

  // 如果提供了组播IP，进行解析
  if (argc >= 4) {
    sz_addr = argv[3];
    if (strlen(sz_addr) <= 0) {
      fprintf(stderr, "ERROR: 参数错误。\n");
      return 1;
    }
    multicast_ip = inet_addr(sz_addr);
  }
  return 0;
}

// 处理接收到的数据的回调函数
void
on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata)
{
  ndn_data_t data;
  printf("收到数据\n");
  
  // 解码数据包并验证其摘要
  if (ndn_data_tlv_decode_digest_verify(&data, rawdata, data_size)) {
    printf("解码失败。\n");
    return;
  }

  // 输出数据内容
  printf("内容为: %s\n", data.content_value);
}

// 超时处理函数
void
on_timeout(void* userdata)
{
  printf("请求超时\n");
  running = false;
}

// 主函数，初始化NDN和接口，发送兴趣包
int
main(int argc, char *argv[])
{
  ndn_udp_face_t *face;
  ndn_interest_t interest;
  int ret;

  // 解析命令行参数
  if ((ret = parseArgs(argc, argv)) != 0) {
    return ret;
  }

  // 启动NDN-lite库
  ndn_lite_startup();

  // 创建UDP组播接口
  face = ndn_udp_multicast_face_construct(INADDR_ANY, multicast_ip, port);

  // 添加路由到转发器
  ndn_forwarder_add_route_by_name(&face->intf, &name_prefix);

  // 根据名称前缀生成兴趣包
  ndn_interest_from_name(&interest, &name_prefix);

  // 发送兴趣包，指定回调函数
  ndn_forwarder_express_interest_struct(&interest, on_data, on_timeout, NULL);

  running = true;

  // 循环处理NDN事件
  while (running) {
    ndn_forwarder_process();
    usleep(10000);  // 休眠10毫秒
  }

  // 销毁接口
  ndn_face_destroy(&face->intf);
  return 0;
}
