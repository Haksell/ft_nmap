#include "ft_nmap.h"

extern volatile sig_atomic_t run;
extern pthread_mutex_t mutex_run;

#define TCP_FILTERED 0b0010011000001110
#define UDP_FILTERED 0b0010011000000110

static void calculate_latency(t_thread_info* th_info, uint8_t* reply_packet) {
    uint64_t now = get_microseconds();
    struct timeval* tv = (struct timeval*)reply_packet;
    th_info->latency = now - tv->tv_sec * 1000000 - tv->tv_usec;
}

static void handle_icmp(t_thread_info* th_info, const u_char* packet, const struct ip* ip) {
    uint32_t icmp_offset = SIZE_ETHERNET + ip->ip_hl * 4;
    struct icmphdr* icmp = (struct icmphdr*)(packet + icmp_offset);

    if (icmp->type == ICMP_ECHOREPLY) {
        calculate_latency(th_info, (uint8_t*)(packet + icmp_offset + ICMP_HDR_SIZE));
    } else if (icmp->type == ICMP_DEST_UNREACH) {
        uint16_t mask = (1 << icmp->code);

        uint32_t original_ip_offset = icmp_offset + ICMP_HDR_SIZE;
        struct ip* original_ip = (struct ip*)(packet + original_ip_offset);
        uint32_t original_ip_hdr_len = original_ip->ip_hl * 4;

        uint8_t* original_packet = (uint8_t*)(packet + original_ip_offset + original_ip_hdr_len);
        uint16_t original_port;

        if (th_info->current_scan == SCAN_UDP) {
            struct udphdr* udp = (struct udphdr*)(original_packet);
            original_port = ntohs(udp->uh_dport);
        } else {
            struct tcphdr* tcp = (struct tcphdr*)(original_packet);
            original_port = ntohs(tcp->th_dport);
        }

        t_port_state port_state = th_info->current_scan == SCAN_UDP
                                      ? (mask & UDP_FILTERED               ? PORT_FILTERED
                                         : mask & (1 << ICMP_PORT_UNREACH) ? PORT_CLOSED
                                                                           : PORT_UNEXPECTED)
                                      : (mask & TCP_FILTERED ? PORT_FILTERED : PORT_UNEXPECTED);

        set_port_state(th_info, port_state, original_port);
    }
}

static void handle_tcp(t_thread_info* th_info, const u_char* packet, const struct ip* ip, uint32_t size_ip) {
    const struct tcphdr* tcp = (struct tcphdr*)(packet + SIZE_ETHERNET + size_ip);

    uint32_t size_tcp = tcp->th_off * 4;
    if (size_tcp < 20) {
        if (th_info->nmap->opt & OPT_VERBOSE) printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }

    t_port_state port_state;
    pthread_mutex_lock(&mutex_run);
    switch (th_info->current_scan) {
        case SCAN_SYN:
            port_state = tcp->th_flags == (TH_SYN | TH_ACK) ? PORT_OPEN
                         : tcp->th_flags & TH_RST           ? PORT_CLOSED
                                                            : PORT_UNEXPECTED;
            break;
        case SCAN_ACK:
            if (tcp->th_flags & TH_RST) port_state = PORT_UNFILTERED;
            break;
        case SCAN_WIN:
            if (tcp->th_flags & TH_RST) port_state = tcp->th_win ? PORT_OPEN : PORT_CLOSED;
            break;
        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS:
            if (tcp->th_flags & TH_RST) port_state = PORT_CLOSED;
            break;
    }
    pthread_mutex_unlock(&mutex_run);

    set_port_state(th_info, port_state, ntohs(tcp->th_sport));

    uint32_t size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    if (size_payload > 0 && th_info->nmap->opt & OPT_VERBOSE)
        print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
}

static void handle_udp(t_thread_info* th_info, const u_char* packet, uint32_t size_ip) {
    const struct udphdr* udp = (struct udphdr*)(packet + SIZE_ETHERNET + size_ip);

    if ((ntohs(udp->uh_dport) ^ ntohs(udp->uh_sport)) != th_info->port_source) return;

    if (th_info->nmap->opt & OPT_VERBOSE) {
        printf(
            "UDP src port: %d dest port: %d length: %d\n",
            ntohs(udp->uh_sport),
            ntohs(udp->uh_dport),
            ntohs(udp->uh_ulen)
        );
    }

    set_port_state(th_info, PORT_OPEN, ntohs(udp->uh_sport));
}

static void got_packet(u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header, const u_char* packet) {
    t_thread_info* th_info = (t_thread_info*)args;

    const struct ip* ip = (struct ip*)(packet + SIZE_ETHERNET);
    uint32_t size_ip = ip->ip_hl * 4;
    if (size_ip < 20) {
        if (th_info->nmap->opt & OPT_VERBOSE) printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    th_info->host->is_up = true;
    if (ip->ip_p == IPPROTO_ICMP) handle_icmp(th_info, packet, ip);
    else if (ip->ip_p == IPPROTO_TCP) handle_tcp(th_info, packet, ip, size_ip);
    else if (ip->ip_p == IPPROTO_UDP) handle_udp(th_info, packet, size_ip);
}

void* capture_packets(void* args) {
    t_thread_info* th_info = ((t_capture_args*)args)->th_info;
    t_nmap* nmap = th_info->nmap;
    pcap_t* handle = ((t_capture_args*)args)->handle;
    while (run) {
        int ret = pcap_dispatch(handle, -1, got_packet, (void*)th_info);
        if (ret == PCAP_ERROR_NOT_ACTIVATED || ret == PCAP_ERROR) error("pcap_loop failed");
        if (ret == PCAP_ERROR_BREAK) {
            pthread_mutex_lock(&mutex_run);
            bool should_break = (th_info->globals.sender_finished || !run);
            pthread_mutex_unlock(&mutex_run);
            if (should_break) break;
            unset_filters(nmap, th_info->t_index);
        }
    }
    return NULL;
}
