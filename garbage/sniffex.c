#define APP_NAME "sniffex"
#define APP_DESC "Sniffer example using libpcap"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#define FILTER_EXP "ip"
#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN 6
#define NUM_PACKETS 10

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

void print_app_usage() {
    printf("Usage: " APP_NAME " [interface]\n");
    printf("Options:\n");
    printf("    interface    Listen on <interface> for packets.\n");
}

void print_hex_ascii_line(const u_char* payload, int len, int offset) {
    int i;
    int gap;
    const u_char* ch;

    printf("%05d   ", offset);

    ch = payload;
    for (i = 0; i < 16; i++) {
        if (i < len) {
            printf("%02x ", *ch);
            ch++;
        } else printf("   ");
        if (i == 7) printf(" ");
    }

    printf("   ");

    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%c", isprint(*ch) ? *ch : '.');
        ch++;
    }
    printf("\n");
}

void print_payload(const u_char* payload, int len) {
    // TODO: code this shit properly
    int len_rem = len;
    int line_width = 16;
    int line_len;
    int offset = 0;
    const u_char* ch = payload;

    if (len <= 0) return;

    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    for (;;) {
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch, line_len, offset);
        len_rem -= line_len;
        ch += line_len;
        offset += line_width;
        if (len_rem <= line_width) {
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    static int count = 1;

    printf("\nPacket number %d:\n", count);
    count++;

    const struct sniff_ethernet* ethernet = (struct sniff_ethernet*)(packet);

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

    const u_char* payload = (u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0) {
        printf("   Payload (%d bytes):\n", size_payload);
        print_payload(payload, size_payload);
    }
}

int main(int argc, char** argv) {
    char* dev = NULL;
    char errbuf[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    bpf_u_int32 mask, net;
    pcap_if_t* devs = NULL;

    printf(APP_NAME " - " APP_DESC "\n");

    if (argc == 2) {
        dev = argv[1];
    } else if (argc == 2) {
        if (pcap_findalldevs(&devs, errbuf) == PCAP_ERROR) {
            fprintf(stderr, "Couldn't find all devices: %s\n", errbuf);
            exit(EXIT_FAILURE);
        }
        dev = devs->name;
    } else {
        fprintf(stderr, "error: unrecognized command-line options\n");
        print_app_usage();
        exit(EXIT_FAILURE);
    }

    if (pcap_lookupnet(dev, &net, &mask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = mask = 0;
    }

    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", NUM_PACKETS);
    printf("Filter expression: %s\n", FILTER_EXP);

    pcap_t* handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        exit(EXIT_FAILURE);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        fprintf(stderr, "%s is not an Ethernet\n", dev);
        exit(EXIT_FAILURE);
    }
    if (pcap_compile(handle, &fp, FILTER_EXP, 0, net) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    pcap_loop(handle, NUM_PACKETS, got_packet, NULL);
    if (devs) pcap_freealldevs(devs);
    pcap_freecode(&fp);
    pcap_close(handle);
    printf("\nCapture complete.\n");
    return EXIT_SUCCESS;
}
