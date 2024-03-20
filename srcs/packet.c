#include "ft_nmap.h"

struct pseudohdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

uint16_t calculate_checksum(uint16_t* data, size_t length) {
    uint32_t sum = 0;

    for (size_t i = 0; i < length / 2; ++i) {
        sum += data[i];
    }

    if (length & 1) {
        sum += ((uint8_t*)data)[length - 1] << 8;
    }

    while (sum >> 16) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)~sum;
}

uint16_t tcp_checksum(void* pseudohdr, void* tcphdr) {
    size_t packet_size = sizeof(struct pseudohdr) + sizeof(struct tcphdr);
    uint8_t checksum_packet[packet_size];

    memcpy(checksum_packet, pseudohdr, sizeof(struct pseudohdr));
    memcpy(checksum_packet + sizeof(struct pseudohdr), tcphdr, sizeof(struct tcphdr));

    return calculate_checksum((uint16_t*)checksum_packet, packet_size);
}

void fill_packet(uint8_t* packet, struct sockaddr_in target, short port) {
    struct tcphdr tcphdr = {
        .source = htons(37216), // TODO! randomize
        .dest = htons(port),
        .seq = 0, // TODO! randomize peut etre
        .ack_seq = 0, // a voir apres pour ACK
        .doff = 5, // 5 * 32 bits = 160 bits = 20 bytes || sur nmap Header Length: 24 bytes (6)
        .fin = 0,
        .syn = 1,
        .rst = 0,
        .psh = 0,
        .ack = 0,
        .urg = 0,
        .window = htons(1024), // pas sur
        .check = 0,
        .urg_ptr = 0,
    };

    struct iphdr iphdr = {
        .version = 4,
        .ihl = 5,
        .tos = 0,
        .tot_len = htons(sizeof(iphdr) + sizeof(tcphdr)),
        .id = htons(random_u32_range(0, UINT16_MAX)),
        .frag_off = 0,
        .ttl = random_u32_range(33, 63),
        .protocol = IPPROTO_TCP,
        .check = 0,
        .saddr = get_source_address(), // spoof possible?
        .daddr = target.sin_addr.s_addr,
    };

    iphdr.check = calculate_checksum((uint16_t*)&iphdr, sizeof(iphdr));

    struct pseudohdr pseudohdr = {
        .saddr = iphdr.saddr,
        .daddr = iphdr.daddr,
        .reserved = 0,
        .protocol = iphdr.protocol,
        .tcp_length = htons(sizeof(tcphdr)),
    };

    tcphdr.check = tcp_checksum(&pseudohdr, &tcphdr);

    memcpy(packet, &iphdr, sizeof(iphdr));
    memcpy(packet + sizeof(iphdr), &tcphdr, sizeof(tcphdr));
}

// static void set_tcp_flags(struct tcphdr* tcph, int type) {
//     tcph->urg = 0, tcph->ack = 0, tcph->psh = 0, tcph->rst = 0, tcph->syn = 0, tcph->fin = 0;

//     switch (type) {
//         case SCAN_SYN: tcph->syn = 1; break;
//         case SCAN_NULL: break;
//         case SCAN_ACK: tcph->ack = 1; break;
//         case SCAN_FIN: tcph->fin = 1; break;
//         case SCAN_XMAS:
//             tcph->fin = 1;
//             tcph->urg = 1;
//             tcph->psh = 1;
//             break;
//     }
// }