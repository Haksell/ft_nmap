#include "ft_nmap.h"

extern bool run;
extern pcap_t* handle;

// static void print_hex_line(const u_char* payload, int len) {
//     for (int i = 0; i < LINE_WIDTH; ++i) {
//         if (i < len) printf("%02x ", *payload);
//         else printf("   ");
//         ++payload;
//         if (i == 7) printf(" ");
//     }
// }

// static void print_ascii_line(const u_char* payload, int len) {
//     for (int i = 0; i < len; ++i) {
//         printf("%c", isprint(*payload) ? *payload : '.');
//         ++payload;
//     }
// }

// static void print_hex_ascii_line(const u_char* payload, int len, int offset) {
//     printf("%05x   ", offset);
//     print_hex_line(payload, len);
//     printf("   ");
//     print_ascii_line(payload, len);
//     printf("\n");
// }

// static void print_payload(const u_char* payload, int size_payload) {
//     printf("   Payload (%d bytes):\n", size_payload);
//     for (int offset = 0; size_payload > 0; size_payload -= LINE_WIDTH) {
//         print_hex_ascii_line(payload + offset, MIN(size_payload, LINE_WIDTH), offset);
//         offset += LINE_WIDTH;
//     }
// }

static void got_packet(u_char* args, __attribute__((unused)) const struct pcap_pkthdr* header, const u_char* packet) {
    t_nmap* nmap = (t_nmap*)args;

    // TODO: work with other things than internet
    // TODO: LORENZO utiliser vrai struct ip et struct tcp pour aleger le code
    const struct sniff_ip* ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    int size_ip = IP_HL(ip) * 4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return; // TODO VOIR CAS LIMITE, EST CE QUE CA SERT LE PRINT OU JUSTE RETURN
    }

    // todo switch case pour les types de paquets
    // handle_icmp handle_tcp handle_udp
    if (ip->ip_p == IPPROTO_ICMP) {
        struct icmphdr* icmp = (struct icmphdr*)(packet + SIZE_ETHERNET + size_ip);
        if (icmp->type == ICMP_ECHOREPLY) {
            handle_echo_reply(nmap, (uint8_t*)(packet + SIZE_ETHERNET + size_ip + ICMP_HDR_SIZE));
        } else if (icmp->type == ICMP_DEST_UNREACH) {
            printf("Destination unreachable\n");
            // TCP FIN, NULL, XMAS, ACK, SYN
            // ICMP unreachable error (type 3, code 1, 2, 3, 9, 10, or 13)? FILTERED!

            // UDP
            // ICMP unreachable error (type 3, code 1, 2, 9, 10, or 13)	? FILTERED!
            // ICMP port unreachable error (type 3, code 3)	? CLOSED!
        } else if (icmp->type == ICMP_TIME_EXCEEDED) {
            printf("Time exceeded\n"); // Voir le nmap book si ça va servir, sinon delete
        } else {
            printf("Si ça arrive, screenshot sur discord: %d\n", icmp->type); // normalement on devrait pas arriver ici
        }
        return;
    }
    if (ip->ip_p != IPPROTO_TCP) return; // pour l'instant ok

    const struct sniff_tcp* tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);

    int size_tcp = TH_OFF(tcp) * 4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return; // TODO VOIR CAS LIMITE, EST CE QUE CA SERT LE PRINT OU JUSTE RETURN
    }

    // POUR LE RENDU FINAL, ON DOIT FAIRE UN TABLEAU DE PORTS OUVERTS ET FERMES POUR CHAQUE SCAN TYPE? A REFLECHIR
    port_state port_state;
    switch (nmap->current_scan) {
        case SCAN_NUM_SYN:
            port_state = tcp->th_flags == (TH_SYN | TH_ACK)   ? PORT_OPEN
                         : tcp->th_flags == (TH_RST | TH_ACK) ? PORT_CLOSED
                                                              : PORT_FILTERED;
            break;
        case SCAN_NUM_UDP: port_state = PORT_OPEN; break;
        case SCAN_NUM_ACK:
            // port_state = tcp->th_flags == (TH_RST) ? PORT_UNFILTERED : PORT_FILTERED;
            break;
        default: // SCAN_NUM_NULL, SCAN_NUM_FIN, SCAN_NUM_XMAS
            port_state = tcp->th_flags == (TH_RST | TH_ACK) ? PORT_CLOSED : PORT_UNDEFINED; // OPEN FILTERED
            break;
    }

    nmap->port_states[nmap->hostname_index][0][nmap->port_dictionary[ntohs(tcp->th_sport)]] = port_state;
    --nmap->undefined_count[nmap->hostname_index];

    // int size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
    // if (size_payload > 0) print_payload((u_char*)(packet + SIZE_ETHERNET + size_ip + size_tcp), size_payload);
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

        for (int i = 0; i < nmap->port_count; ++i) { // moche
            switch (nmap->current_scan) {
                case SCAN_NUM_SYN:
                    if (nmap->port_states[nmap->hostname_index][0][i] == PORT_UNDEFINED) {
                        nmap->port_states[nmap->hostname_index][0][i] = PORT_FILTERED;
                    }
                    break;
                case SCAN_NUM_UDP:
                    ///
                    break;
                case SCAN_NUM_ACK:
                    ///
                    break;
                default: // SCAN_NUM_NULL, SCAN_NUM_FIN, SCAN_NUM_XMAS
                    if (nmap->port_states[nmap->hostname_index][0][i] == PORT_UNDEFINED) {
                        nmap->port_states[nmap->hostname_index][0][i] = PORT_OPEN; // PORT_FILTERED EN FAIT
                    }
                    break;
            }
        }
        nmap->undefined_count[nmap->hostname_index] = 0;
    }
    return NULL;
}
