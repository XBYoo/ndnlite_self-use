// config.h
#define LOCAL_UDP_PORT_A 6363
#define LOCAL_UDP_PORT_C 6364
#define PEER_IP_A "192.168.1.100"
#define PEER_IP_C "192.168.1.102"
#define PEER_UDP_PORT_A 6363
#define PEER_UDP_PORT_C 6363


#include "ndn-lite.h"
#include "ndn-lite/forwarder/forwarder.h"
#include "ndn-lite/forwarder/face.h"

// 初始化NDN-Lite
ndn_lite_bootstrap();

// 创建转发器实例
const ndn_forwarder_t* forwarder = ndn_forwarder_get();



// 中继节点实现
void relay_node_init() {
    // 创建两个face，分别用于连接A和C
    ndn_face_t* face_to_A;
    ndn_face_t* face_to_C;
    
    // 配置face（这里以UDP face为例）
    ndn_udp_face_construct(face_to_A, LOCAL_UDP_PORT_A, PEER_IP_A, PEER_UDP_PORT_A);
    ndn_udp_face_construct(face_to_C, LOCAL_UDP_PORT_C, PEER_IP_C, PEER_UDP_PORT_C);
    
    // 注册FIB表项
    ndn_fib_entry_t* fib_entry;
    name_component_t name_components[2];
    // 配置转发规则
    ndn_forwarder_add_route(forwarder, face_to_C, name_prefix, name_prefix_size);
    ndn_forwarder_add_route(forwarder, face_to_A, name_prefix, name_prefix_size);
}

// 处理兴趣包的回调函数
void on_interest(const uint8_t* interest, uint32_t interest_size,
                void* userdata) {
    // 转发兴趣包
    ndn_forwarder_express_interest(forwarder, 
                                 interest,
                                 interest_size,
                                 on_data,
                                 on_timeout,
                                 NULL);
}

// 处理数据包的回调函数
void on_data(const uint8_t* data, uint32_t data_size,
             void* userdata) {
    // 转发数据包
    ndn_forwarder_put_data(forwarder, data, data_size);
}


int main() {
    // 初始化中继节点
    relay_node_init();
    
    // 主循环
    while (1) {
        // 处理待处理的包
        ndn_forwarder_process();
        // 可以添加适当的延时
        usleep(10000);
    }
    
    return 0;
}
