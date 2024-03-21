#include "ft_nmap.h"

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
    static int count = 0;
    ++count;
    printf("\nPacket number %d:\n", count);

    t_nmap* nmap = (t_nmap*)args;

    // TODO: work with other things than internet
    const struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return; // TODO VOIR CAS LIMITE, EST CE QUE CA SERT LE PRINT OU JUSTE RETURN
    }

    printf("       From: %s\n", inet_ntoa(ip->ip_src));
    printf("         To: %s\n", inet_ntoa(ip->ip_dst));
    printf(
        "   Protocol: %s\n", ip->ip_p == IPPROTO_TCP    ? "TCP"
                             : ip->ip_p == IPPROTO_UDP  ? "UDP"
                             : ip->ip_p == IPPROTO_ICMP ? "ICMP"
                             : ip->ip_p == IPPROTO_IP   ? "IP"
                                                        : "unknown"
    );
    if (ip->ip_p != IPPROTO_TCP) return;

    const struct sniff_tcp* tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

    // on ignore si pas pour nous:
    if (nmap->port_source != ntohs(tcp->th_dport)) {
        printf("on a recu de la merde"); // TODO FILTRE
        return;
    }

    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return; // TODO VOIR CAS LIMITE, EST CE QUE CA SERT LE PRINT OU JUSTE RETURN
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
}

void* capture_packets(void* nmap) {
    pcap_loop(handle, -1, got_packet, nmap);
    return NULL;
}
