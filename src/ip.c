#include "ip.h"

#include "arp.h"
#include "ethernet.h"
#include "icmp.h"
#include "net.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    // Step1: 检查数据包长度是否小于 IP 头部最小长度（20字节）
    if (buf->len < sizeof(ip_hdr_t)) {
        return;  // 数据包不完整，丢弃
    }

    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    // Step2: 报头检测：版本号必须为 IPv4，总长度字段不能超过数据包实际长度
    if (ip_hdr->version != IP_VERSION_4) {
        return;  // 非IPv4协议，丢弃
    }
    int ip_hdr_len = ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE;
    uint16_t total_len = swap16(ip_hdr->total_len16);  // 使用 swap16 替代 ntohs
    if (ip_hdr_len < sizeof(ip_hdr_t) || total_len > buf->len) {
        return;  // 头部长度异常或总长度超出，丢弃
    }

    // Step3: 校验头部校验和
    uint16_t old_checksum = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    uint16_t new_checksum = checksum16((uint16_t *)ip_hdr, ip_hdr_len);
    ip_hdr->hdr_checksum16 = old_checksum;

    if (new_checksum != old_checksum) {
        return;  // 校验失败，数据损坏，丢弃
    }

    // Step4: 对比目的IP地址是否是本机
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) {
        return;  // 不是发给本机的IP包，丢弃
    }

    // Step5: 去除填充字段
    if (buf->len > total_len) {
        buf_remove_padding(buf, buf->len - total_len);
    }

    // Step6: 去掉IP报头
    buf_remove_header(buf, ip_hdr_len);

    // Step7: 向上层传递数据包
    if (net_in(buf, ip_hdr->protocol, ip_hdr->src_ip) < 0) {
        // 协议无法识别，发送 ICMP 协议不可达
        icmp_unreachable(buf, ip_hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
    }
}
/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf) {
   // Step1: 增加头部缓存空间
    if (buf_add_header(buf, IP_HDR_LEN) < 0) {
        return;  // 添加头部失败，丢弃该包
    }

    // Step2: 填写头部字段
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;

    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = IP_HDR_LEN / 4;  // 单位是 4 字节
    ip_hdr->tos = 0;                           // 服务类型暂设为0
    ip_hdr->total_len16 = swap16(buf->len);    // 使用 swap16 替代 htons
    ip_hdr->id16 = swap16(id);                 // 使用 swap16 替代 htons
    ip_hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | (offset));  // 使用 swap16 替代 htons
    ip_hdr->ttl = 64;                          // 默认 TTL
    ip_hdr->protocol = protocol;               // 上层协议类型
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);  // 源IP地址
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);        // 目的IP地址

    // Step3: 计算并填写校验和
    ip_hdr->hdr_checksum16 = 0;
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, IP_HDR_LEN);

    // Step4: 发送数据
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    static uint16_t ip_id = 0;  
    const int MAX_PAYLOAD = ETHERNET_MAX_TRANSPORT_UNIT - IP_HDR_LEN;
    int remaining = buf->len;
    int offset_bytes = 0;

    while (remaining > 0) {
        int frag_size = (remaining > MAX_PAYLOAD) ? MAX_PAYLOAD : remaining;
        int mf = (remaining > MAX_PAYLOAD) ? 1 : 0;

        // 创建一个新的 buf 用于当前分片
        buf_t frag_buf;
        buf_init(&frag_buf, frag_size);

        // 拷贝当前分片的数据到新缓冲区
        memcpy(frag_buf.data, buf->data + offset_bytes, frag_size);
        frag_buf.len = frag_size;

        // 发送该分片，注意偏移是以 8 字节为单位
        ip_fragment_out(&frag_buf, ip, protocol, ip_id, offset_bytes / 8, mf);

        // 更新偏移量和剩余长度
        offset_bytes += frag_size;
        remaining -= frag_size;
    }

    ip_id++;  
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}