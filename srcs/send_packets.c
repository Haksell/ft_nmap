#include "ft_nmap.h"

extern sig_atomic_t run;
extern sig_atomic_t sender_finished;

#define NTP1                                                                                                           \
    "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5O#Kq\xb1R\xf3"
#define NTP2                                                                                                           \
    "\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" \
    "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\xf1^\xdbx\x00\x00\x00"
#define NTP_SIZE 48

static void send_packet(t_nmap* nmap, uint16_t port) {
    uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    size_t packet_size = sizeof(struct iphdr) +
                         (nmap->current_scan == SCAN_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));

    if (port == 123 && nmap->current_scan == SCAN_UDP) {
        uint8_t packetntp[sizeof(struct iphdr) + sizeof(struct udphdr) + NTP_SIZE];
        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + NTP_SIZE;
        unsigned char payload[4][48] = {NTP1, NTP2, NTP1, NTP2}; // TODO: only 2?
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

static bool is_host_down(t_nmap* nmap) { // faire un select avec timeout? plus propre mais aussi long
    int old_hostname_up_count = nmap->hostname_up_count;
    struct timeval countdown = {.tv_usec = 300000}; // 3s -> MACRO
    while (nmap->hostname_up_count == old_hostname_up_count && countdown.tv_usec > 0 && run) {
        usleep(1000);
        countdown.tv_usec -= 1000;
    }
    if (countdown.tv_usec <= 0) {
        // a print uniquement si le seul host est down, donc pas ici // Lorenzo
        printf("Host %s is down.\n", nmap->hostnames[nmap->hostname_index]);
        return true;
    }
    return false;
}

void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    for (nmap->hostname_index = 0; nmap->hostname_index < nmap->hostname_count; ++nmap->hostname_index) {
        hostname_to_ip(nmap); // TODO if unkown host continue
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        // TODO: local hostaddr. ça veut dire quoi?
        send_ping(nmap);
        if (is_host_down(nmap)) continue;

        for (scan_type scan = 0; scan < SCAN_MAX; ++scan) {
            if ((nmap->scans & (1 << scan)) == 0) continue;
            nmap->current_scan = scan;

            nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
            set_filter(nmap);

            // TODO: shuffle
            for (int port_index = 0; port_index < nmap->port_count && run; ++port_index) {
                if (nmap->current_scan == SCAN_UDP) sleep(1);
                send_packet(nmap, nmap->port_array[port_index]);
            }

            alarm(1); // TODO: alarm(2)
            // TODO: no forbidden functions
            while (nmap->undefined_count[nmap->hostname_index][nmap->current_scan] > 0) usleep(1000);
            alarm(0);

            // Pourquoi on rentre la-dedans que pour le dernier scan ?
            for (int i = 0; i < nmap->port_count; ++i) {
                if (nmap->port_states[nmap->hostname_index][nmap->current_scan][i] == PORT_UNDEFINED) {
                    nmap->port_states[nmap->hostname_index][nmap->current_scan]
                                     [i] = default_port_state[nmap->current_scan];
                } else if (!nmap->is_responsive[nmap->hostname_index][i]) {
                    printf(
                        "ooga port=%d scan=%d\n",
                        nmap->port_array[i],
                        nmap->port_states[nmap->hostname_index][nmap->current_scan][i]
                    );
                    ++nmap->responsive_count[nmap->hostname_index];
                    nmap->is_responsive[nmap->hostname_index][i] = true;
                }
            }
            sender_finished = true;
        }
        print_scan_report(nmap);
    }
    handle_sigint(SIGINT); // TODO: not like thats
    return NULL;
}
