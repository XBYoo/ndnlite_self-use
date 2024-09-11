/*
 * Copyright (C) 2019 Xinyu Ma, Zhiyi Zhang
 *
 * 本文件遵循GNU较宽松通用公共许可证v3.0的条款和条件。有关更多详细信息，请参阅顶层目录中的LICENSE文件。
 *
 * 查看AUTHORS.md获取NDN IOT PKG的贡献者名单。
 */

#include <stdio.h>       // 标准输入输出库
#include <netdb.h>       // 网络数据库库，提供主机名解析和IP地址操作
#include <unistd.h>      // 提供POSIX操作系统API，如usleep()用于睡眠
#include <stdlib.h>      // 提供内存管理、进程控制等函数
#include <ndn-lite.h>    // NDN-Lite核心库，支持NDN网络协议功能
#include "ndn-lite/encode/name.h"      // 编码和解析NDN名字的函数
#include "ndn-lite/encode/data.h"      // 编码和解析NDN数据包的函数
#include "ndn-lite/encode/interest.h"  // 编码和解析NDN兴趣包的函数

in_port_t port1, port2;     // 定义本地和远程的端口号
in_addr_t server_ip;        // 定义远程服务器IP地址
ndn_name_t name_prefix;     // 定义NDN名字前缀，用于构造兴趣包和数据包
bool running;               // 控制程序主循环是否运行的标志

/*
 * 函数：parseArgs
 * 解析命令行参数，提取本地端口、远程IP、远程端口和NDN名字前缀。
 * 返回值：
 *   0 - 成功
 *   1 - 错误的参数数量或格式
 *   2 - 无效的主机名
 *   3 - 无效的端口号
 *   4 - 无效的NDN名字前缀
 */
int
parseArgs(int argc, char *argv[])
{
  char *sz_port1, *sz_port2, *sz_addr;   // 用于存储命令行参数
  uint32_t ul_port;                      // 存储端口号的临时变量
  struct hostent * host_addr;            // 存储主机信息的结构体
  struct in_addr ** paddrs;              // 指向IP地址列表的指针

  // 检查参数数量是否足够
  if(argc < 5) {
    fprintf(stderr, "ERROR: wrong arguments.\n");
    printf("Usage: <local-port> <remote-ip> <remote-port> <name-prefix>\n");
    return 1;
  }
  
  sz_port1 = argv[1]; // 本地端口
  sz_addr = argv[2];  // 远程服务器IP地址
  sz_port2 = argv[3]; // 远程服务器端口

  // 检查端口和IP地址的有效性
  if(strlen(sz_port1) <= 0 || strlen(sz_addr) <= 0 || strlen(sz_port2) <= 0){
    fprintf(stderr, "ERROR: wrong arguments.\n");
    return 1;
  }

  // 通过主机名解析远程IP地址
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
  server_ip = paddrs[0]->s_addr;  // 获取远程IP地址

  // 将本地端口转换为整数，并检查其范围
  ul_port = strtoul(sz_port1, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port1 = htons((uint16_t) ul_port);  // 转换为网络字节序

  // 将远程端口转换为整数，并检查其范围
  ul_port = strtoul(sz_port2, NULL, 10);
  if(ul_port < 1024 || ul_port >= 65536){
    fprintf(stderr, "ERROR: wrong port number.\n");
    return 3;
  }
  port2 = htons((uint16_t) ul_port);

  // 解析并检查NDN名字前缀的有效性
  if(ndn_name_from_string(&name_prefix, argv[4], strlen(argv[4])) != NDN_SUCCESS){
    fprintf(stderr, "ERROR: wrong name.\n");
    return 4;
  }

  return 0;
}

/*
 * 函数：on_data
 * 当接收到数据包时被调用，解码并输出数据包的内容。
 */
void
on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata)
{
  ndn_data_t data;  // 定义NDN数据包结构
  printf("On data\n");
  
  // 尝试对接收到的数据进行解码和验证签名
  if (ndn_data_tlv_decode_digest_verify(&data, rawdata, data_size)) {
    printf("Decoding failed.\n");
  }
  
  // 输出数据包的内容
  printf("It says: %s\n", data.content_value);
  
  // 设置运行标志为false，停止主循环
  running = false;
}

/*
 * 函数：on_timeout
 * 当兴趣包超时时被调用，输出超时信息并停止程序。
 */
void
on_timeout(void* userdata) {
  printf("On timeout\n");
  running = false;
}

/*
 * 主函数：main
 * 通过NDN网络表达兴趣包，监听数据包响应，并进行超时处理。
 */
int
main(int argc, char *argv[])
{
  ndn_udp_face_t *face;  // 定义UDP通信的“face”
  ndn_interest_t interest;  // 定义NDN兴趣包结构
  int ret;

  // 解析命令行参数并检查其有效性
  if((ret = parseArgs(argc, argv)) != 0){
    return ret;
  }

  ndn_lite_startup();  // 初始化NDN-Lite的核心组件

  // 创建一个UDP通信面，用于本地和远程的通信
  face = ndn_udp_unicast_face_construct(INADDR_ANY, port1, server_ip, port2);

  // 在NDN转发器中为名字前缀添加路由
  ndn_forwarder_add_route_by_name(&face->intf, &name_prefix);

  // 构造兴趣包，并使用名字前缀作为其名称
  ndn_interest_from_name(&interest, &name_prefix);

  // 通过转发器发送兴趣包，设置数据和超时回调
  ndn_forwarder_express_interest_struct(&interest, on_data, on_timeout, NULL);

  running = true;  // 设置运行标志为true，进入主循环

  // 主循环：不断处理NDN转发器中的兴趣包和数据包
  while(running) {
    ndn_forwarder_process();  // 处理转发器中的数据和事件
    usleep(10000);  // 每次处理后休眠10毫秒
  }

  // 程序结束时销毁UDP通信面
  ndn_face_destroy(&face->intf);
  return 0;
}
