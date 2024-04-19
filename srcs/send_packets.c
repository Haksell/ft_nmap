#include "ft_nmap.h"
#include <stdint.h>
#include <sys/types.h>

extern sig_atomic_t run;
extern sig_atomic_t sender_finished;
extern pcap_t *handle_lo, *handle_net, *current_handle;

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

static bool is_host_down(t_nmap* nmap) {
    uint8_t buffer[64] = {0}; //  a refaire avec socket a partir de l'autre thread

    int bytes_received = recv(nmap->icmp_fd, buffer, sizeof(buffer), 0);
    if (bytes_received < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            printf("Host %s is down.\n", nmap->hosts[nmap->h_index].name);
            return true;
        } else error("recv failed");
    } else if (bytes_received == 0) {
        printf("Host %s is down.\n", nmap->hosts[nmap->h_index].name);
        return true;
    }

    return false;
}

void* send_packets(void* arg) {
    t_nmap* nmap = (t_nmap*)arg;
    uint16_t* loop_port_array = nmap->opt & OPT_RANDOMIZE ? nmap->port_array : nmap->random_port_array;
    for (nmap->h_index = 0; nmap->h_index < nmap->hostname_count && run; ++nmap->h_index) {
        if (!hostname_to_ip(nmap)) continue;
        nmap->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(nmap->hostip)};
        send_ping(nmap);
        if (is_host_down(nmap)) continue;
        current_handle = (nmap->hostaddr.sin_addr.s_addr & 255) == 127 ? handle_lo : handle_net;

        for (scan_type scan = 0; scan < SCAN_MAX && run; ++scan) {
            if ((nmap->scans & (1 << scan)) == 0) continue;
            nmap->current_scan = scan;

            nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
            set_filter(nmap);
            for (int port_index = 0; port_index < nmap->port_count && run; ++port_index) {
                if (nmap->current_scan == SCAN_UDP) sleep(1); // TODO: NO
                send_packet(nmap, loop_port_array[port_index]);
            }

            alarm(1); // TODO: alarm(2)
            // TODO: no forbidden functions
            while (nmap->hosts[nmap->h_index].undefined_count[nmap->current_scan] > 0 && run) usleep(1000);
            alarm(0);
            unset_filters(nmap);

            for (int i = 0; i < nmap->port_count; ++i) {
                if (nmap->hosts[nmap->h_index].port_states[nmap->current_scan][i] == PORT_UNDEFINED) {
                    nmap->hosts[nmap->h_index]
                        .port_states[nmap->current_scan][i] = default_port_state[nmap->current_scan];
                }
            }
            sender_finished = true;
        }
        if (run) print_scan_report(nmap);
    }
    handle_sigint(SIGINT); // TODO: not like that
    return NULL;
}
