#include "ft_nmap.h"

struct pseudohdr {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t reserved;
    uint8_t protocol;
    uint16_t tcp_length;
};

static uint16_t calculate_checksum(uint16_t* data, size_t length) {
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

static uint16_t checksum(void* pseudohdr, void* hdr, size_t hdr_size, void* payload, size_t payload_size) {
    size_t packet_size = sizeof(struct pseudohdr) + hdr_size + payload_size;
    uint8_t checksum_packet[packet_size];

    memcpy(checksum_packet, pseudohdr, sizeof(struct pseudohdr));
    memcpy(checksum_packet + sizeof(struct pseudohdr), hdr, hdr_size);
    if (payload) memcpy(checksum_packet + sizeof(struct pseudohdr) + hdr_size, payload, payload_size);

    return calculate_checksum((uint16_t*)checksum_packet, packet_size);
}

static void set_tcp_flags(struct tcphdr* tcph, scan_type type) {
    switch (type) {
        case SCAN_SYN: tcph->syn = 1; break;
        case SCAN_NULL: break;
        case SCAN_ACK: tcph->ack = 1; break;
        case SCAN_FIN: tcph->fin = 1; break;
        case SCAN_XMAS:
            tcph->fin = 1;
            tcph->urg = 1;
            tcph->psh = 1;
            break;
        default: break;
    }
}

static struct udphdr fill_udp_header(t_nmap* nmap, uint16_t port, size_t payload_size) {
    struct udphdr udphdr = {
        .source = htons(nmap->port_source),
        .dest = htons(port),
        .len = htons(sizeof(udphdr) + payload_size),
        .check = 0,
    };

    return udphdr;
}

static struct tcphdr fill_tcp_header(t_nmap* nmap, uint16_t port) {
    struct tcphdr tcphdr = {
        .source = htons(nmap->port_source), // randomize, mais que au debut
        .dest = htons(port),
        .seq = 0, // TODO! randomize peut etre
        .ack_seq = 0, // a voir apres pour ACK
        .doff = 5, // 5 * 32bits = 20 bytes || sur nmap : 24 bytes
        .fin = 0,
        .syn = 0,
        .rst = 0,
        .psh = 0,
        .ack = 0,
        .urg = 0,
        .window = htons(1024), // pas sur
        .check = 0,
        .urg_ptr = 0,
    };

    set_tcp_flags(&tcphdr, nmap->current_scan);

    return tcphdr;
}

void fill_packet(t_nmap* nmap, uint8_t* packet, uint16_t port, uint8_t* payload, size_t payload_size) {
    struct tcphdr tcphdr;
    struct udphdr udphdr;
    uint16_t hdr_size = nmap->current_scan == SCAN_UDP ? sizeof(udphdr) : sizeof(tcphdr);

    if (nmap->current_scan == SCAN_UDP) udphdr = fill_udp_header(nmap, port, payload_size);
    else tcphdr = fill_tcp_header(nmap, port);

    struct iphdr iphdr = {
        .version = 4,
        .ihl = 5,
        .tos = 0,
        .tot_len = htons(sizeof(iphdr) + hdr_size + payload_size),
        .id = htons(random_u32_range(0, UINT16_MAX)), // a verifier
        .frag_off = 0,
        .ttl = random_u32_range(33, 63),
        .protocol = nmap->current_scan == SCAN_UDP ? IPPROTO_UDP : IPPROTO_TCP,
        .check = 0,
        .saddr = get_source_address(), // spoof possible?
        .daddr = nmap->hostaddr.sin_addr.s_addr,
    };

    iphdr.check = calculate_checksum((uint16_t*)&iphdr, sizeof(iphdr));

    struct pseudohdr pseudohdr = {
        .saddr = iphdr.saddr,
        .daddr = iphdr.daddr,
        .reserved = 0,
        .protocol = iphdr.protocol,
        .tcp_length = htons(hdr_size + payload_size),
    };

    if (nmap->current_scan == SCAN_UDP)
        udphdr.check = checksum(&pseudohdr, &udphdr, sizeof(udphdr), payload, payload_size);
    else tcphdr.check = checksum(&pseudohdr, &tcphdr, sizeof(tcphdr), payload, payload_size);

    memcpy(packet, &iphdr, sizeof(iphdr));
    if (nmap->current_scan == SCAN_UDP) {
        memcpy(packet + sizeof(iphdr), &udphdr, sizeof(udphdr));
        if (payload) memcpy(packet + sizeof(iphdr) + sizeof(udphdr), payload, payload_size);
    } else memcpy(packet + sizeof(iphdr), &tcphdr, sizeof(tcphdr));
}
