#include "ft_nmap.h"

extern sig_atomic_t run;
extern sig_atomic_t sender_finished;
extern pcap_t* current_handle;

#define TCP_FILTERED 0b0010011000001110
#define UDP_FILTERED 0b0010011000000110

static void set_port_state(t_nmap* nmap, port_state port_state, uint16_t port) {
    if (nmap->hosts[nmap->h_index].port_states[nmap->current_scan][nmap->port_dictionary[port]] == PORT_UNDEFINED) {
        nmap->hosts[nmap->h_index].port_states[nmap->current_scan][nmap->port_dictionary[port]] = port_state;
        --nmap->hosts[nmap->h_index].undefined_count[nmap->current_scan];
        if (nmap->hosts[nmap->h_index].undefined_count[nmap->current_scan] == 0) pcap_breakloop(current_handle);
    }
}

static void handle_icmp(t_nmap* nmap, const u_char* packet, const struct ip* ip) {
    int icmp_offset = SIZE_ETHERNET + ip->ip_hl * 4;
    struct icmphdr* icmp = (struct icmphdr*)(packet + icmp_offset);

    if (icmp->type == ICMP_ECHOREPLY) {
        handle_echo_reply(nmap, (uint8_t*)(packet + icmp_offset + ICMP_HDR_SIZE));
    } else if (icmp->type == ICMP_DEST_UNREACH) {
        uint16_t mask = (1 << icmp->code);

        int original_ip_offset = icmp_offset + ICMP_HDR_SIZE;
        struct ip* original_ip = (struct ip*)(packet + original_ip_offset);
        int original_ip_hdr_len = original_ip->ip_hl * 4;

        uint8_t* original_packet = (uint8_t*)(packet + original_ip_offset + original_ip_hdr_len);
        uint16_t original_port;

        if (nmap->current_scan == SCAN_UDP) {
            struct udphdr* udp = (struct udphdr*)(original_packet);
            original_port = ntohs(udp->uh_dport);
        } else {
            struct tcphdr* tcp = (struct tcphdr*)(original_packet);
            original_port = ntohs(tcp->th_dport);
        }

        port_state port_state = nmap->current_scan == SCAN_UDP
                                    ? (mask & UDP_FILTERED               ? PORT_FILTERED
                                       : mask & (1 << ICMP_PORT_UNREACH) ? PORT_CLOSED
                                                                         : PORT_UNEXPECTED)
                                    : (mask & TCP_FILTERED ? PORT_FILTERED : PORT_UNEXPECTED);

        set_port_state(nmap, port_state, original_port);
    }
}

static void handle_tcp(t_nmap* nmap, const u_char* packet, const struct ip* ip, int size_ip) {
    const struct tcphdr* tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);

    int size_tcp = tcp->th_off * 4;
    if (size_tcp < 20) {
        if (nmap->opt & OPT_VERBOSE) printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    port_state port_state;
    switch (nmap->current_scan) {
        case SCAN_SYN:
            port_state = tcp->th_flags == (TH_SYN | TH_ACK) ? PORT_OPEN
                         : tcp->th_flags & TH_RST           ? PORT_CLOSED
                                                            : PORT_UNEXPECTED;
            break;
        case SCAN_ACK: port_state = tcp->th_flags & TH_RST ? PORT_UNFILTERED : PORT_UNEXPECTED; break;
        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS: port_state = tcp->th_flags & TH_RST ? PORT_CLOSED : PORT_UNEXPECTED; break;
    }

    set_port_state(nmap, port_state, ntohs(tcp->th_sport));

    int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0 && nmap->opt & OPT_VERBOSE)
        print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
}

static void handle_udp(t_nmap* nmap, const u_char* packet, /* const struct ip* ip*/ int size_ip) {
    const struct udphdr* udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);

    if (ntohs(udp->uh_dport) != nmap->port_source) return;

    if (nmap->opt & OPT_VERBOSE) {
        printf(
            "UDP src port: %d dest port: %d length: %d\n",
            ntohs(udp->uh_sport),
            ntohs(udp->uh_dport),
            ntohs(udp->uh_ulen)
        );
    }

    set_port_state(nmap, PORT_OPEN, ntohs(udp->uh_sport));
}

static void got_packet(u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header, const u_char* packet) {
    t_nmap* nmap = (t_nmap*)args;

    const struct ip* ip = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = ip->ip_hl * 4;
    if (size_ip < 20) {
        if (nmap->opt & OPT_VERBOSE) printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    // printf("IP_p type: %d\n", ip->ip_p);
    if (ip->ip_p == IPPROTO_ICMP) handle_icmp(nmap, packet, ip);
    else if (ip->ip_p == IPPROTO_TCP) handle_tcp(nmap, packet, ip, size_ip);
    else if (ip->ip_p == IPPROTO_UDP) handle_udp(nmap, packet, size_ip);
}

void* capture_packets(void* args) {
    t_nmap* nmap = ((capture_args*)args)->nmap;
    pcap_t* handle = ((capture_args*)args)->handle;
    while (run) {
        int ret = pcap_loop(handle, -1, got_packet, (void*)nmap);
        if (ret == PCAP_ERROR_NOT_ACTIVATED || ret == PCAP_ERROR) error("pcap_loop failed");
        nmap->hosts[nmap->h_index].undefined_count[nmap->current_scan] = 0;
        while (run && !sender_finished) usleep(1000);
        sender_finished = false;
    }
    return NULL;
}
