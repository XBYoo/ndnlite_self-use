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
#include <arpa/inet.h>
#include <ndn-lite.h>
#include "../adaptation/udp/udp-face.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"

// 全局变量：端口号，多播IP地址，名称前缀，数据缓冲区，UDP接口，运行状态
in_port_t port;
in_addr_t multicast_ip;
ndn_name_t name_prefix;
uint8_t buf[4096];
ndn_udp_face_t *face;
bool running;

// 解析命令行参数的函数
int parseArgs(int argc, char *argv[])
{
  char *sz_port, *sz_addr;
  uint32_t ul_port;

  // 检查命令行参数数量
  if (argc < 2) {
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <name-prefix> <port>=56363 <group-ip>=224.0.23.170\n");
    return 1;
  }

  // 解析名称前缀
  if (ndn_name_from_string(&name_prefix, argv[1], strlen(argv[1])) != NDN_SUCCESS) {
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  // 设置默认端口号和多播IP地址
  uint32_t portnum = 56363;
  port = htons(portnum);
  multicast_ip = inet_addr("224.0.23.170");

  // 如果提供了端口号参数
  if (argc >= 3) {
    sz_port = argv[2];
    if (strlen(sz_port) <= 0) {
      fprintf(stderr, "ERROR: wrong arguments.\n");
      return 1;
    }
    ul_port = strtoul(sz_port, NULL, 10);
    if (ul_port < 1024 || ul_port >= 65536) {
      fprintf(stderr, "ERROR: wrong port number.\n");
      return 3;
    }
    port = htons((uint16_t) ul_port);
  }

  // 如果提供了多播IP地址参数
  if (argc >= 4) {
    sz_addr = argv[3];
    if (strlen(sz_addr) <= 0) {
      fprintf(stderr, "ERROR: wrong arguments.\n");
      return 1;
    }
    multicast_ip = inet_addr(sz_addr);
  }

  return 0;
}

// 处理收到的兴趣包的回调函数
int on_interest(const uint8_t* interest, uint32_t interest_size, void* userdata)
{
  ndn_interest_t interest_pkt;
  ndn_interest_from_block(&interest_pkt, interest, interest_size);
  ndn_data_t data;
  ndn_encoder_t encoder;
  char * str = "I'm a Data packet.'\0'";

  printf("On interest\n");
  // 设置数据包的名称
  data.name = interest_pkt.name;
  // 设置数据包内容
  ndn_data_set_content(&data, (uint8_t*)str, strlen(str));
  ndn_metainfo_init(&data.metainfo);
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);
  // 编码数据包
  encoder_init(&encoder, buf, 4096);
  ndn_data_tlv_encode_digest_sign(&encoder, &data);
  ndn_forwarder_put_data(encoder.output_value, encoder.offset);

  return NDN_FWD_STRATEGY_SUPPRESS; // 阻止进一步转发
}

// 主函数
int main(int argc, char *argv[])
{
  int ret;

  // 解析命令行参数
  if ((ret = parseArgs(argc, argv)) != 0) {
    return ret;
  }

  // 启动ndn-lite
  ndn_lite_startup();
  // 创建UDP多播接口
  face = ndn_udp_multicast_face_construct(INADDR_ANY, multicast_ip, port);
  // 注册名称前缀，并设置回调函数处理兴趣包
  ndn_forwarder_register_name_prefix(&name_prefix, on_interest, NULL);

  running = true;
  while (running) {
    // 处理NDN转发器事件
    ndn_forwarder_process();
    usleep(10000); // 休眠10毫秒
  }

  // 销毁接口
  ndn_face_destroy(&face->intf);
  return 0;
}
