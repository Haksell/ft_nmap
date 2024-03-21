#include "ft_nmap.h"

extern bool run;
extern pcap_t* handle;

static void print_hex_line(const u_char* payload, int len) {
    for (int i = 0; i < LINE_WIDTH; ++i) {
        if (i < len) printf("%02x ", *payload);
        else printf("   ");
        ++payload;
        if (i == 7) printf(" ");
    }
}

static void print_ascii_line(const u_char* payload, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%c", isprint(*payload) ? *payload : '.');
        ++payload;
    }
}

static void print_hex_ascii_line(const u_char* payload, int len, int offset) {
    printf("%05x   ", offset);
    print_hex_line(payload, len);
    printf("   ");
    print_ascii_line(payload, len);
    printf("\n");
}

static void print_payload(const u_char* payload, int size_payload) {
    printf("   Payload (%d bytes):\n", size_payload);
    for (int offset = 0; size_payload > 0; size_payload -= LINE_WIDTH) {
        print_hex_ascii_line(payload + offset, MIN(size_payload, LINE_WIDTH), offset);
        offset += LINE_WIDTH;
    }
}

static void got_packet(u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header, const u_char* packet) {
    t_nmap* nmap = (t_nmap*)args;

    // TODO: work with other things than internet
    const struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return; // TODO VOIR CAS LIMITE, EST CE QUE CA SERT LE PRINT OU JUSTE RETURN
    }

    // printf(
    //     "   Protocol: %s\n", ip->ip_p == IPPROTO_TCP    ? "TCP"
    //                          : ip->ip_p == IPPROTO_UDP  ? "UDP"
    //                          : ip->ip_p == IPPROTO_ICMP ? "ICMP"
    //                          : ip->ip_p == IPPROTO_IP   ? "IP"
    //                                                     : "unknown"
    // );
    if (ip->ip_p != IPPROTO_TCP) return; // pour l'instant ok

    const struct sniff_tcp* tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return; // TODO VOIR CAS LIMITE, EST CE QUE CA SERT LE PRINT OU JUSTE RETURN
    }

    nmap->port_states[nmap->hostname_index][nmap->port_dictionary[ntohs(tcp->th_sport)]] =
        tcp->th_flags == (TH_SYN | TH_ACK)   ? PORT_OPEN
        : tcp->th_flags == (TH_RST | TH_ACK) ? PORT_CLOSED
                                             : PORT_FILTERED;
    --nmap->undefined_count[nmap->hostname_index];

    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
}

void* capture_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    while (run) {
        pcap_loop(handle, -1, got_packet, arg);
        for (int i = 0; i < nmap->port_count; ++i) {
            // for SYN
            if (nmap->port_states[nmap->hostname_index][i] == PORT_UNDEFINED) {
                nmap->port_states[nmap->hostname_index][i] = PORT_FILTERED;
            }
        }
        nmap->undefined_count[nmap->hostname_index] = 0;
    }
    return NULL;
}
