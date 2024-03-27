#include "ft_nmap.h"

extern bool run;
extern pcap_t* handle;

#define TCP_FILTERED 0b0010011000001110
#define UDP_FILTERED 0b0010011000000110

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

        // si t'arrives a faire un truc plus propre que ca c'est bien. PORT_UNDEFINED est superflu. Ou non?
        port_state port_state = nmap->current_scan == SCAN_UDP ? (mask & UDP_FILTERED               ? PORT_FILTERED
                                                                  : mask & (1 << ICMP_PORT_UNREACH) ? PORT_CLOSED
                                                                                                    : PORT_UNDEFINED)
                                                               : (mask & TCP_FILTERED ? PORT_FILTERED : PORT_UNDEFINED);

        nmap->port_states[nmap->hostname_index][nmap->current_scan][nmap->port_dictionary[original_port]] = port_state;
        if (port_state != PORT_UNDEFINED) --nmap->undefined_count[nmap->hostname_index][nmap->current_scan];
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
    // si t'arrives a faire un truc plus propre que ca c'est bien. PORT_UNDEFINED est superflu
    // a discuter si laisser undefined et attendre l'alarme, ou mettre la suite logique
    switch (nmap->current_scan) {
        case SCAN_SYN:
            port_state = tcp->th_flags == (TH_SYN | TH_ACK)   ? PORT_OPEN
                         : tcp->th_flags == (TH_RST | TH_ACK) ? PORT_CLOSED
                                                              : PORT_UNDEFINED;
            break;
        case SCAN_ACK:
            port_state = (tcp->th_flags == (TH_RST) || tcp->th_flags == (TH_RST | TH_ACK))
                             ? PORT_UNFILTERED
                             : PORT_UNDEFINED; // bug trouvé: ./ft_nmap scanme.nmap.org -sACK -p 1-500 != nmap.org . Je
                                               // pense probleme de buffer. notre nmap mets trop peu de temps.
                                               // l'original il s'arrête quand le buffer est plein
            break; // localhost envoi RST et scanme ACK RST, a verifier pour le reste. Peut etre eviter == et faire un
                   // bitwise pour rendre propre ?
        case SCAN_NULL:
        case SCAN_FIN:
        case SCAN_XMAS: port_state = tcp->th_flags == (TH_RST | TH_ACK) ? PORT_CLOSED : PORT_UNDEFINED; break;
    }

    nmap->port_states[nmap->hostname_index][nmap->current_scan]
                     [nmap->port_dictionary[ntohs(tcp->th_sport)]] = port_state;

    if (port_state != PORT_UNDEFINED) --nmap->undefined_count[nmap->hostname_index][nmap->current_scan];

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

    nmap->port_states[nmap->hostname_index][nmap->current_scan]
                     [nmap->port_dictionary[ntohs(udp->uh_sport)]] = PORT_OPEN;
    --nmap->undefined_count[nmap->hostname_index][nmap->current_scan];
}

static void got_packet(u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header, const u_char* packet) {
    t_nmap* nmap = (t_nmap*)args;

    const struct ip* ip = (struct ip*)(packet + SIZE_ETHERNET);
    int size_ip = ip->ip_hl * 4;
    if (size_ip < 20) {
        if (nmap->opt & OPT_VERBOSE) printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }

    if (ip->ip_p == IPPROTO_ICMP) handle_icmp(nmap, packet, ip);
    else if (ip->ip_p == IPPROTO_TCP) handle_tcp(nmap, packet, ip, size_ip);
    else if (ip->ip_p == IPPROTO_UDP) handle_udp(nmap, packet, size_ip);
}

void* capture_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    while (run) {
        int ret = pcap_loop(handle, -1, got_packet, arg);
        /*
        With the pcap functions available, another approach is to ensure that your packet processing is as efficient as
        possible to minimize the risk of buffer overflow and packet drops.

        Dispatch Packets Quickly: Use pcap_dispatch() effectively to process packets as quickly as they are captured.
        The faster you can process packets, the less likely you are to encounter buffer overflow issues.

        Filtering: Use pcap_compile() and pcap_setfilter() to apply a filter that limits the captured traffic to only
        what's necessary for your scanning task. By reducing the amount of unnecessary traffic pcap has to handle, you
        can mitigate the impact of not being able to increase the buffer size.
        */
        if (ret == PCAP_ERROR_NOT_ACTIVATED || ret == PCAP_ERROR) {
            error("pcap_loop failed");
            exit(EXIT_FAILURE);
        }

        for (int i = 0; i < nmap->port_count; ++i) {
            if (nmap->port_states[nmap->hostname_index][nmap->current_scan][i] != PORT_UNDEFINED) continue;
            // TODO: axbrisse: array of default states
            switch (nmap->current_scan) {
                case SCAN_SYN:
                case SCAN_ACK: nmap->port_states[nmap->hostname_index][nmap->current_scan][i] = PORT_FILTERED; break;
                case SCAN_NULL:
                case SCAN_FIN:
                case SCAN_XMAS:
                case SCAN_UDP:
                    nmap->port_states[nmap->hostname_index][nmap->current_scan][i] = PORT_OPEN_FILTERED;
                    break;
            }
        }
        nmap->undefined_count[nmap->hostname_index][nmap->current_scan] = 0;
    }
    return NULL;
}
