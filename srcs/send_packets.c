#include "ft_nmap.h"
#include <signal.h>

extern bool run;

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

static uint16_t tcp_checksum(void* pseudohdr, void* tcphdr) {
    size_t packet_size = sizeof(struct pseudohdr) + sizeof(struct tcphdr);
    uint8_t checksum_packet[packet_size];

    memcpy(checksum_packet, pseudohdr, sizeof(struct pseudohdr));
    memcpy(checksum_packet + sizeof(struct pseudohdr), tcphdr, sizeof(struct tcphdr));

    return calculate_checksum((uint16_t*)checksum_packet, packet_size);
}

static void fill_packet(uint8_t* packet, t_nmap* nmap, uint16_t port) {
    struct tcphdr tcphdr = {
        .source = htons(nmap->port_source), // randomize, mais que au debut
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
        .daddr = nmap->hostaddr.sin_addr.s_addr,
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

void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    for (; nmap->hostname_index < nmap->hostname_count; ++nmap->hostname_index) {
        printf("%d", nmap->undefined_count[nmap->hostname_index]);
        alarm(5);
        hostname_to_ip(nmap);
        // TODO: local hostaddr
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
        // TODO: shuffle
        for (int j = 0; j < nmap->port_count && run; ++j) {
            uint16_t port = nmap->port_array[j];
            uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
            fill_packet(packet, nmap, port);
            sendto(nmap->fd, packet, NMAP_PACKET_SIZE, 0, (struct sockaddr*)&nmap->hostaddr, sizeof(nmap->hostaddr));
        }

        while (nmap->undefined_count[nmap->hostname_index] > 0) usleep(1000); // TODO: no forbidden functions
        alarm(0);

        printf("\nNmap scan report for %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
        printf("Host is up (0.0019s latency).\n"); // TODO LORENZO PING
        printf(
            "rDNS record for %s: fra15s10-in-f14.1e100.net\n", nmap->hostnames[nmap->hostname_index]
        ); // TODO LORENZO DNS uniquement s'il a trouve le dns

        // if (0)
        //     printf("Not shown: 58 filtered tcp ports (no-response)\n");

        printf("PORT   STATE SERVICE\n"); // TODO align styleeeeee'

        for (int j = 0; j < nmap->port_count; ++j) {
            // port_state state = nmap->port_states[nmap->hostname_index][j];
            // if (state != PORT_FILTERED && state != PORT_CLOSED) {
            printf(
                "%d/tcp %s  http\n", nmap->port_array[j], port_state_str[nmap->port_states[nmap->hostname_index][j]]
            );
            // }
        }
    }
    handle_sigint(SIGINT);
    return NULL;
}
