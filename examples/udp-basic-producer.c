/*
 * Copyright (C) 2019 Xinyu Ma, Zhiyi Zhang
 *
 * This file是由GNU Lesser General Public License v3.0许可的。
 * 详情请查看LICENSE文件，了解更多条款与条件。
 *
 * 查看AUTHORS.md获取NDN IOT PKG的贡献者名单。
 */

#include <stdio.h>       // 标准输入输出库
#include <netdb.h>       // 提供网络数据库操作函数
#include <unistd.h>      // 提供POSIX操作系统API，如usleep()
#include <stdlib.h>      // 提供内存分配、进程控制等函数
#include <ndn-lite.h>    // NDN-Lite库，核心的NDN功能和协议实现
#include "ndn-lite/encode/name.h"      // NDN名字相关的编码功能
#include "ndn-lite/encode/data.h"      // NDN数据包相关的编码功能
#include "ndn-lite/encode/interest.h"  // NDN兴趣包相关的编码功能

in_port_t port1, port2;     // 定义本地和远程端口
in_addr_t server_ip;        // 定义远程服务器IP
ndn_name_t name_prefix;     // 定义NDN名字前缀
uint8_t buf[4096];          // 数据缓存区，用于存放编码后的数据包
ndn_udp_face_t *face;       // 定义UDP通信的“face”（面），用于NDN通信
bool running;               // 控制程序主循环的运行状态

/*
 * 函数：parseArgs
 * 解析命令行参数，提取本地端口、远程IP、远程端口和名字前缀。
 * 返回值：
 *   0 - 成功
 *   1 - 错误的命令行参数
 *   2 - 无效的主机名
 *   3 - 无效的端口号
 *   4 - 无效的NDN名字前缀
 */
int
parseArgs(int argc, char *argv[])
{
  char *sz_port1, *sz_port2, *sz_addr;   // 用于存放命令行参数
  uint32_t ul_port;                      // 用于端口号的临时变量
  struct hostent * host_addr;            // 主机地址结构体
  struct in_addr ** paddrs;              // 用于存放解析出的IP地址

  // 参数数量不够，输出用法并返回错误
  if (argc < 5) {
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <remote-ip> <remote-port> <name-prefix>\n");
    return 1;
  }

  sz_port1 = argv[1]; // 本地端口
  sz_addr = argv[2];  // 远程IP地址
  sz_port2 = argv[3]; // 远程端口

  // 检查参数的有效性
  if(strlen(sz_port1) <= 0 || strlen(sz_addr) <= 0 || strlen(sz_port2) <= 0){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }

  // 根据主机名获取IP地址
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
  server_ip = paddrs[0]->s_addr;  // 保存解析到的远程服务器IP地址

  // 将字符串的本地端口转换为整数，并检查范围
  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port1 = htons((uint16_t) ul_port);  // 将主机字节序的端口号转换为网络字节序

  // 将字符串的远程端口转换为整数，并检查范围
  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port2 = htons((uint16_t) ul_port);

  // 将名字前缀从字符串转换为NDN格式，并检查其有效性
  if(ndn_name_from_string(&name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  return 0;
}

/*
 * 函数：on_interest
 * 当接收到NDN兴趣包时调用，生成对应的NDN数据包并返回给请求者。
 */
int
on_interest(const uint8_t* interest, uint32_t interest_size, void* userdata)
{
  ndn_data_t data;  // 定义NDN数据包结构体
  ndn_encoder_t encoder;  // 定义编码器
  char * str = "I'm a Data packet.";  // 数据包内容

  printf("On interest\n");
  data.name = name_prefix;  // 使用全局的名字前缀
  ndn_data_set_content(&data, (uint8_t*)str, strlen(str) + 1);  // 设置数据包内容
  ndn_metainfo_init(&data.metainfo);  // 初始化元信息
  ndn_metainfo_set_content_type(&data.metainfo, NDN_CONTENT_TYPE_BLOB);  // 设置数据包类型
  encoder_init(&encoder, buf, 4096);  // 初始化编码器
  ndn_data_tlv_encode_digest_sign(&encoder, &data);  // 对数据包进行TLV编码并签名
  ndn_forwarder_put_data(encoder.output_value, encoder.offset);  // 将数据包发送到转发器

  return NDN_FWD_STRATEGY_SUPPRESS;  // 抑制策略，用于控制NDN的转发策略
}

/*
 * 主函数：main
 * 初始化NDN网络，并启动监听兴趣包请求。
 */
int
main(int argc, char *argv[])
{
  int ret;
  
  // 解析命令行参数并检查错误
  if ((ret = parseArgs(argc, argv)) != 0) {
    return ret;
  }

  ndn_lite_startup();  // 启动NDN-Lite的核心组件

  // 创建一个NDN UDP单播面，用于本地和远程的通信
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip, port2);

  // 注册名字前缀和对应的兴趣包处理函数
  ndn_forwarder_register_name_prefix(&name_prefix, on_interest, NULL);

  running = true;  // 设置运行状态为true，进入主循环

  // 主循环：不断处理NDN转发器中的兴趣包
  while (running) {
    ndn_forwarder_process();  // 处理转发器中的兴趣包
    usleep(10000);  // 每次处理完后休眠10毫秒
  }

  // 程序结束时销毁NDN face
  ndn_face_destroy(&face->intf);
  return 0;
}
