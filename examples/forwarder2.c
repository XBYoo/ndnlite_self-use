#include <ndn-lite.h>
//#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/encode/name.h"
#include "ndn-lite/encode/data.h"
#include "ndn-lite/encode/interest.h"
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>


// 数据包处理回调函数
void on_data(const uint8_t* rawdata, uint32_t data_size, void* userdata) {
    printf("中继节点收到数据包。\n");

    // 解码数据
    ndn_data_t data;
    if (ndn_data_tlv_decode_digest_verify(&data, rawdata, data_size) != NDN_SUCCESS) {
        printf("数据解码失败。\n");
        return;
    }

    // 创建编码器
    ndn_encoder_t encoder;
    uint8_t encoded_name[256];
    ndn_encoder_init(&encoder, encoded_name, sizeof(encoded_name));

    // 编码名称
    if (ndn_name_tlv_encode(&encoder, &data.name) != NDN_SUCCESS) {
        printf("名称编码失败。\n");
        return;
    }

    size_t encoded_name_size = ndn_encoder_get_offset(&encoder);

    // 查找或插入内容存储
    ndn_cs_entry_t* cs_entry = ndn_cs_find_or_insert(ndn_forwarder_get()->cs, encoded_name, encoded_name_size);
    if (cs_entry) {
        ndn_insert_cs_entry_with_content(cs_entry, (uint8_t*)rawdata, data_size);
        printf("数据存储成功。\n");
    }
}

// 主函数
int main(int argc, char *argv[]) {
    if (argc < 5) {
        printf("Usage: %s <consumer-port> <producer-ip> <producer-port> <producer-prefix>\n", argv[0]);
        return 1;
    }

    // 启动 NDN-Lite
    ndn_lite_startup();

    // 解析参数
    in_port_t consumer_port = htons(atoi(argv[1]));
    in_addr_t producer_ip = inet_addr(argv[2]);
    in_port_t producer_port = htons(atoi(argv[3]));

    // 创建 face
    ndn_udp_face_t* consumer_face = ndn_udp_unicast_face_construct(INADDR_ANY, consumer_port, INADDR_ANY, 0);
    ndn_udp_face_t* producer_face = ndn_udp_unicast_face_construct(INADDR_ANY, 0, producer_ip, producer_port);

    // 注册前缀
    const char* prefix = "/example";
    ndn_name_t name_prefix;
    ndn_name_from_string(&name_prefix, prefix, strlen(prefix));
    ndn_forwarder_register_prefix((uint8_t*)prefix, strlen(prefix), NULL, NULL);
    ndn_forwarder_add_route_by_name(&producer_face->intf, &name_prefix);

    // 模拟事件循环
    while (1) {
        ndn_forwarder_process();
        usleep(10000); // 休眠 10 毫秒
    }

    return 0;
}

