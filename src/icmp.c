#include "icmp.h"

#include "ip.h"
#include "net.h"

/**
 * @brief 发送icmp响应
 *
 * @param req_buf 收到的icmp请求包
 * @param src_ip 源ip地址
 */
static void icmp_resp(buf_t *req_buf, uint8_t *src_ip) {
     // Step1: 初始化并封装数据
    buf_init(&txbuf, req_buf->len);
    memcpy(txbuf.data, req_buf->data, req_buf->len);

    // Step2: 修改ICMP类型为Echo Reply（0），并计算校验和
    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    hdr->type = 0;
    hdr->code = 0;
    hdr->checksum16 = 0;
    hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, txbuf.len));

    // Step3: 发送数据报
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);
}

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_ip 源ip地址
 */
void icmp_in(buf_t *buf, uint8_t *src_ip) {
    // Step1: 报头检测
    if (buf->len < 8) return;

    // Step2: 查看ICMP类型是否为Echo Request
    icmp_hdr_t *hdr = (icmp_hdr_t *)buf->data;
    if (hdr->type == 8) { // Echo Request
        // Step3: 回复Echo Reply
        icmp_resp(buf, src_ip);
    }
}

/**
 * @brief 发送icmp不可达
 *
 * @param recv_buf 收到的ip数据包
 * @param src_ip 源ip地址
 * @param code icmp code，协议不可达或端口不可达
 */
void icmp_unreachable(buf_t *recv_buf, uint8_t *src_ip, icmp_code_t code) {
    // Step1: 初始化并填写ICMP首部（8字节）+ 原始IP头部和前8字节数据
    size_t data_len = 20 + 8;
    buf_init(&txbuf, 8 + data_len);

    icmp_hdr_t *hdr = (icmp_hdr_t *)txbuf.data;
    hdr->type = 3;  // Destination Unreachable
    hdr->code = code;
    hdr->checksum16 = 0;
    hdr->id16 = 0;
    hdr->seq16 = 0;

    // Step2: 拷贝原始IP头 + 前8字节数据到ICMP数据部分
    memcpy(txbuf.data + 8, recv_buf->data, data_len);

    // Step3: 计算校验和
    hdr->checksum16 = swap16(checksum16((uint16_t *)txbuf.data, txbuf.len));

    // Step4: 发送
    ip_out(&txbuf, src_ip, NET_PROTOCOL_ICMP);

}

/**
 * @brief 初始化icmp协议
 *
 */
void icmp_init() {
    net_add_protocol(NET_PROTOCOL_ICMP, icmp_in);
}