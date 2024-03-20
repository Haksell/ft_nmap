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

void got_packet(
    __attribute__((unused)) u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header, const u_char* packet
) {
    static int count = 0;
    ++count;
    printf("\nPacket number %d:\n", count);

    // TODO: work with other things than internet
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
    if (size_payload > 0) print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
}

void init_pcap(capture_args_t* capture_args) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev;

    if (pcap_findalldevs(&capture_args->devs, errbuf) == PCAP_ERROR) panic("Couldn't find all devices: %s\n", errbuf);
    dev = capture_args->devs->name;

    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", NUM_PACKETS);
    printf("Filter expression: %s\n", FILTER_EXP);

    bpf_u_int32 _, net;
    if (pcap_lookupnet(dev, &net, &_, errbuf) == PCAP_ERROR)
        panic("Couldn't get netmask for device %s: %s\n", dev, errbuf);

    capture_args->handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
    if (capture_args->handle == NULL) panic("Couldn't open device %s: %s\n", dev, errbuf);
    handle = capture_args->handle; // TODO: clean this garbage
    if (pcap_datalink(capture_args->handle) != DLT_EN10MB) panic("%s is not an Ethernet\n", dev);
    struct bpf_program fp;
    if (pcap_compile(capture_args->handle, &fp, FILTER_EXP, 0, net) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", FILTER_EXP, pcap_geterr(capture_args->handle));
    if (pcap_setfilter(capture_args->handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", FILTER_EXP, pcap_geterr(capture_args->handle));
    pcap_freecode(&fp);
}

void* capture_packets(__attribute__((unused)) void* arg) {
    pcap_loop(((capture_args_t*)arg)->handle, NUM_PACKETS, got_packet, NULL);
    return NULL;
}
