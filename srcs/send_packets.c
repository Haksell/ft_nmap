#include "ft_nmap.h"

extern bool run;

//
/*  Test Ntp (port 123/udp) | A trouver database de payloads pour automatiser les UDP.

    sudo ./ft_nmap scanme.nmap.org -p 68,123,22
    Starting Nmap 0.4.2 at 2024-03-27 04:10 CET

    Nmap scan report for scanme.nmap.org (45.33.32.156)
    Host is up (0.22s latency).
    rDNS record for scanme.nmap.org: fra15s10-in-f14.1e100.net

    PORT | SYN    ACK        FIN           NULL          XMAS            SERVICE | UDP             SERVICE
    22   | open   unfiltered open|filtered open|filtered open|filtered   ssh     | closed          unknown
    68   | closed unfiltered open|filtered open|filtered open|filtered   unknown | open|filtered   bootpc
    123  | closed unfiltered open|filtered open|filtered open|filtered   unknown | >>> open <<<    ntp		<-- NTP (no
   payload == open|filtered)
*/

#define NTP1                                                                                                           \
    "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5O#Kq\xb1R\xf3"
#define NTP2                                                                                                           \
    "\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\xf1^\xdbx\x00\x00\x00"
#define NTP3                                                                                                           \
    "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5O#Kq\xb1R\xf3"
#define NTP4                                                                                                           \
    "\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\xf1^\xdbx\x00\x00\x00"
#define NTP_SIZE 48

static void send_packet(t_nmap* nmap, uint16_t port) {
    uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    size_t packet_size = sizeof(struct iphdr) +
                         (nmap->current_scan == SCAN_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));

    // Test NTP 123/udp open  ntp || sudo ./ft_nmap scanme.nmap.org -p 68,123,22
    if (port == 123 && nmap->current_scan == SCAN_UDP) {
        uint8_t packetntp[sizeof(struct iphdr) + sizeof(struct udphdr) + NTP_SIZE];
        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + NTP_SIZE;
        unsigned char payload[4][48] = {NTP1, NTP2, NTP3, NTP4};
        for (int i = 0; i < 4; i++) {
            fill_packet(nmap, packetntp, port, payload[i], NTP_SIZE);
            sendto(nmap->udp_fd, packetntp, packet_size, 0, (struct sockaddr*)&nmap->hostaddr, sizeof(nmap->hostaddr));
        }
    } else { // tout sans payload
        fill_packet(nmap, packet, port, NULL, 0);
        sendto(
            (nmap->current_scan == SCAN_UDP) ? nmap->udp_fd : nmap->tcp_fd,
            packet,
            packet_size,
            0,
            (struct sockaddr*)&nmap->hostaddr,
            sizeof(nmap->hostaddr)
        );
    }
}

void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    for (; nmap->hostname_index < nmap->hostname_count; ++nmap->hostname_index) {
        hostname_to_ip(nmap);
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        // TODO: local hostaddr. ça veut dire quoi?
        send_ping(nmap);

        // je suis fatigue, donc c'est pas ouf, mais la logique est la.
        // si t'arrives à faire un truc plus elegant, go
        int old_hostname_up_count = nmap->hostname_up_count;
        struct timeval countdown = {.tv_usec = 300000}; // 3s -> MACRO
        while (nmap->hostname_up_count == old_hostname_up_count && countdown.tv_usec > 0 && run) {
            usleep(1000); // 1ms
            countdown.tv_usec -= 1000; // 1ms
        }
        if (countdown.tv_usec <= 0) { // si apres 3s, le hostname_up_count (qui augmente sur ping handle_echo_reply) n'a
                                      // pas change, alors le host est down
            printf(
                "Host %s is down.\n",
                nmap->hostnames[nmap->hostname_index]
            ); // a print uniquement si le seul host est down, donc pas ici // Lorenzo
            continue;
        }

        for (int i = 0; i < SCAN_MAX; ++i) {
            nmap->current_scan = i;
            if ((nmap->scans & (1 << i)) == 0) continue;

            nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
            set_filter(nmap);
            // TODO: shuffle
            for (int j = 0; j < nmap->port_count && run; ++j) {
                send_packet(nmap, nmap->port_array[j]);
            }

            alarm(1);
            while (nmap->undefined_count[nmap->hostname_index][nmap->current_scan] > 0)
                usleep(1000); // TODO: no forbidden functions
            alarm(0);
        }
        print_scan_report(nmap);
    }
    handle_sigint(SIGINT);
    return NULL;
}
