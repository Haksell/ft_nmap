#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define APP_NAME "sniffex"
#define APP_DESC "Sniffer example using libpcap"
#define FILTER_EXP                                                                                 \
    "ip and src host 45.33.32.156 and tcp[tcpflags] & (tcp-syn|tcp-ack) = (tcp-syn|tcp-ack)"
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define NUM_PACKETS 3 // TODO: -1
#define LINE_WIDTH 16

struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN];
    u_char ether_shost[ETHER_ADDR_LEN];
    u_short ether_type;
};

struct sniff_ip {
    u_char ip_vhl;
    u_char ip_tos;
    u_short ip_len;
    u_short ip_id;
    u_short ip_off;
#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff
    u_char ip_ttl;
    u_char ip_p;
    u_short ip_sum;
    struct in_addr ip_src, ip_dst;
};
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip) (((ip)->ip_vhl) >> 4)

typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;
    u_short th_dport;
    tcp_seq th_seq;
    tcp_seq th_ack;
    u_char th_offx2;
#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

static void panic(const char* format, ...) {
    // TODO: free everything
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    exit(EXIT_FAILURE);
}

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

static void got_packet(
    __attribute__((unused)) u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header,
    const u_char* packet
) {
    static int count = 0;
    ++count;
    printf("\nPacket number %d:\n", count);

    const struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
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

    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    printf("   Src port: %d\n", ntohs(tcp->th_sport));
    printf("   Dst port: %d\n", ntohs(tcp->th_dport));

    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0)
        print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
}

static void init_pcap(int argc, char** argv, pcap_if_t** devs, pcap_t** handle) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev;

    if (argc == 1) {
        if (pcap_findalldevs(devs, errbuf) == PCAP_ERROR)
            panic("Couldn't find all devices: %s\n", errbuf);
        dev = (*devs)->name;
    } else if (argc == 2) {
        dev = argv[1];
    } else panic("Usage: " APP_NAME " [interface]\n");

    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", NUM_PACKETS);
    printf("Filter expression: %s\n", FILTER_EXP);

    bpf_u_int32 _, net;
    if (pcap_lookupnet(dev, &net, &_, errbuf) == PCAP_ERROR)
        panic(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);

    *handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (*handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(*handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
    struct bpf_program fp;
    if (pcap_compile(*handle, &fp, FILTER_EXP, 0, net) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(*handle));
    if (pcap_setfilter(*handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(*handle));
    pcap_freecode(&fp);
}

int main(int argc, char** argv) {
    printf(APP_NAME " - " APP_DESC "\n");
    pcap_if_t* devs = NULL;
    pcap_t* handle = NULL;
    init_pcap(argc, argv, &devs, &handle);
    pcap_loop(handle, NUM_PACKETS, got_packet, NULL);
    if (devs) pcap_freealldevs(devs);
    if (handle) pcap_close(handle);
    printf("\nCapture complete.\n");
    return EXIT_SUCCESS;
}
