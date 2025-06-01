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
    // Step1: 检查最小长度
    if (buf->len < 20) return;

    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

    // Step2: 检查版本和总长度合法性
    if (hdr->version != IP_VERSION_4 || swap16(hdr->total_len16) > buf->len) return;

    // Step3: 校验和检查
    uint16_t recv_checksum = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    uint16_t calc_checksum = checksum16((uint16_t *)hdr, 20);
    if (calc_checksum != swap16(recv_checksum)) return;
    hdr->hdr_checksum16 = recv_checksum;

    // Step4: 检查目的IP是否为本机
    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;

    // Step5: 去除填充字段
    uint16_t total_len = swap16(hdr->total_len16);
    if (buf->len > total_len) buf_remove_padding(buf, buf->len - total_len);

    // Step6: 去除IP头部
    buf_remove_header(buf, 20);

    // Step7: 向上层传递数据包
    if (net_in(buf, hdr->protocol, hdr->src_ip) < 0) {
        // 需要重新加回头部发icmp
        buf_add_header(buf, 20);
        memcpy(buf->data, hdr, 20);
        icmp_unreachable(buf, hdr->src_ip, ICMP_CODE_PROTOCOL_UNREACH);
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
    // Step1: 添加IP头部
    buf_add_header(buf, 20);
    ip_hdr_t *hdr = (ip_hdr_t *)buf->data;

    // Step2: 填写IP头部字段
    hdr->version = IP_VERSION_4;
    hdr->hdr_len = 20 / 4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    uint16_t flags_fragment = ((mf & 0x1) << 13) | (offset >> 3);
    hdr->flags_fragment16 = swap16(flags_fragment);
    hdr->ttl = 64;
    hdr->protocol = protocol;
    hdr->hdr_checksum16 = 0;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    // Step3: 计算校验和
    hdr->hdr_checksum16 = swap16(checksum16((uint16_t *)hdr, 20));

    // Step4: 调用ARP层发送
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
    static uint16_t packet_id = 0;
    int mtu = 1500 - 20;

    if (buf->len > mtu) {
        // 分片
        int offset = 0;
        int len = buf->len;

        while (offset < len) {
            int fragment_len = (len - offset > mtu) ? mtu : (len - offset);
            buf_t fragment;
            buf_init(&fragment, fragment_len);
            memcpy(fragment.data, buf->data + offset, fragment_len);

            // MF = 1 说明后面还有分片
            int mf = (offset + fragment_len < len) ? 1 : 0;

            ip_fragment_out(&fragment, ip, protocol, packet_id, offset, mf);
            offset += fragment_len;
        }
    } else {
        // 无需分片
        ip_fragment_out(buf, ip, protocol, packet_id, 0, 0);
    }

    packet_id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() {
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}