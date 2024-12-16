#include <ndn-lite.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "ndn-lite/forwarder/cs.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"



// 内容存储和转发器实例
ndn_forwarder_t forwarder;
ndn_cs_t *content_store;
bool running;  

// 回调函数：处理兴趣包
int on_interest(const uint8_t* interest_name, uint32_t interest_length, void* userdata) {
    printf("收到兴趣包: %.*s\n", (int)interest_length, interest_name);

    // 在内容存储中查找匹配的内容
    ndn_cs_entry_t* cs_entry = ndn_cs_find(content_store, (uint8_t*)interest_name, interest_length);
    if (cs_entry != NULL) {
        // 匹配到内容，返回数据
        ndn_forwarder_put_data(cs_entry->content, cs_entry->content_len);
        printf("内容已找到并返回。\n");
    } else {
        printf("未找到内容，将转发兴趣包。\n");
        // 转发兴趣包（根据需求实现转发逻辑）
    }
    return 0;
}

// 主函数
int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <consumer-port> <producer-ip> <producer-port> <producer-prefix>\n", argv[0]);
        return 1;
    }
    // 启动 NDN-Lite
    ndn_lite_startup();
    // 初始化转发器
    ndn_forwarder_init();

    // 解析参数
    in_port_t consumer_port = htons(atoi(argv[1]));
    in_addr_t producer_ip = inet_addr(argv[2]);
    in_port_t producer_port = htons(atoi(argv[3]));

    // 创建 face
    ndn_udp_face_t* consumer_face = ndn_udp_unicast_face_construct(INADDR_ANY, consumer_port, INADDR_ANY, 0);
    ndn_udp_face_t* producer_face = ndn_udp_unicast_face_construct(INADDR_ANY, 0, producer_ip, producer_port);

    // 注册前缀
    const char* prefix = "/example/ndn";
    ndn_name_t name_prefix;
    ndn_name_from_string(&name_prefix, prefix, strlen(prefix));
    ndn_forwarder_register_prefix((uint8_t*)prefix, strlen(prefix), on_interest, NULL);
    ndn_forwarder_add_route_by_name(&producer_face->intf, &name_prefix);

    // 分配内存并初始化内容存储
    const ndn_forwarder_t* forwarder_instance = ndn_forwarder_get();
    size_t cs_memory_size = NDN_CS_RESERVE_SIZE(10); // 10表示最大存储条目
    void* cs_memory = malloc(cs_memory_size);
    ndn_cs_init(cs_memory, 10, forwarder_instance->nametree);
    content_store = (ndn_cs_t*)cs_memory;


    // 模拟事件循环
    running = true;
    while (running) {
        ndn_forwarder_process(); // 处理转发器事件
    }

    free(cs_memory);
    return 0;
}
