#include "ft_nmap.h"

extern sig_atomic_t run;
extern sig_atomic_t hostname_finished[MAX_HOSTNAMES];
extern sig_atomic_t sender_finished[MAX_HOSTNAMES];
extern pcap_t* handle_lo[MAX_HOSTNAMES];
extern pcap_t* handle_net[MAX_HOSTNAMES];
extern pcap_t* current_handle[MAX_HOSTNAMES];

#define NTP1 "\xe3\x00\x04\xfa\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc5O#Kq\xb1R\xf3"
#define NTP2 "\xd9\x00\x0a\xfa\x00\x00\x00\x00\x00\x01\x04\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\xf1^\xdbx\x00\x00\x00"
#define NTP_SIZE 48

static void send_packet(t_thread_info* th_info, uint16_t port) {
    t_nmap* nmap = th_info->nmap;
    uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    size_t packet_size = sizeof(struct iphdr) + (th_info->current_scan == SCAN_UDP ? sizeof(struct udphdr) : sizeof(struct tcphdr));

    if (port == 123 && th_info->current_scan == SCAN_UDP) {
        uint8_t packetntp[sizeof(struct iphdr) + sizeof(struct udphdr) + NTP_SIZE];
        packet_size = sizeof(struct iphdr) + sizeof(struct udphdr) + NTP_SIZE;
        unsigned char payload[4][48] = {NTP1, NTP2, NTP1, NTP2}; // TODO: only 2?
        for (int i = 0; i < 4; i++) {
            fill_packet(th_info, packetntp, port, payload[i], NTP_SIZE);
            sendto(nmap->udp_fd, packetntp, packet_size, 0, (struct sockaddr*)&th_info->hostaddr, sizeof(th_info->hostaddr));
        }
    } else { // tout sans payload
        fill_packet(th_info, packet, port, NULL, 0);
        sendto((th_info->current_scan == SCAN_UDP) ? nmap->udp_fd : nmap->tcp_fd, packet, packet_size, 0, (struct sockaddr*)&th_info->hostaddr, sizeof(th_info->hostaddr));
    }
}

static bool is_host_down(t_thread_info* th_info) { // TODO: use the brain
    t_nmap* nmap = th_info->nmap;
    uint8_t buffer[64] = {0}; //  a refaire avec socket a partir de l'autre thread

    int bytes_received = recv(nmap->icmp_fd, buffer, sizeof(buffer), 0);
    if (bytes_received < 0) {
        if (errno == EWOULDBLOCK || errno == EAGAIN) {
            printf("Host %s is down.\n", nmap->hosts[th_info->h_index].name);
            return true;
        } else error("recv failed");
    } else if (bytes_received == 0) {
        printf("Host %s is down.\n", nmap->hosts[th_info->h_index].name);
        return true;
    }

    return false;
}

static pthread_t create_capture_thread(t_capture_args* args) {
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, capture_packets, args)) panic("Failed to create the capture thread");
    return thread_id;
}

void* send_packets(void* arg) {
    t_thread_info* th_info = arg;
    t_nmap* nmap = th_info->nmap;
    uint16_t* loop_port_array = nmap->opt & OPT_NO_RANDOMIZE ? nmap->port_array : nmap->random_port_array;

    // TODO: very important
    pthread_t capture_thread_lo = create_capture_thread(&(t_capture_args){.th_info = th_info, .handle = handle_lo[th_info->t_index]});
    pthread_t capture_thread_net = create_capture_thread(&(t_capture_args){.th_info = th_info, .handle = handle_net[th_info->t_index]});

    int step = nmap->num_threads == 0 ? 1 : nmap->num_threads;
    for (th_info->h_index = th_info->t_index; th_info->h_index < nmap->hostname_count && run; th_info->h_index += step) {
        if (!hostname_to_ip(th_info)) continue;
        th_info->latency = 0.0;
        th_info->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(th_info->hostip)};
        bool is_localhost = (th_info->hostaddr.sin_addr.s_addr & 255) == 127;
        current_handle[th_info->t_index] = is_localhost ? handle_lo[th_info->t_index] : handle_net[th_info->t_index];
        if (!(nmap->opt & OPT_NO_PING) && !is_localhost) {
            // TODO: check latency localhost
            set_filter(th_info, true);
            send_ping(th_info);
            if (is_host_down(th_info)) continue;
            unset_filters(nmap, th_info->t_index);
        }

        for (scan_type scan = 0; scan < SCAN_MAX && run; ++scan) {
            if ((nmap->scans & 1 << scan) == 0) continue;
            th_info->current_scan = scan;

            th_info->port_source = random_u32_range(1 << 15, UINT16_MAX - MAX_PORTS);
            set_filter(th_info, false);
            for (int port_index = 0; port_index < nmap->port_count && run; ++port_index) {
                if (th_info->current_scan == SCAN_UDP && port_index > 6) usleep(1000000);
                send_packet(th_info, loop_port_array[port_index]);
            }

            // TODO: clean this timeout
            int i = 0;
            while (nmap->hosts[th_info->h_index].undefined_count[th_info->current_scan] > 0 && run && i++ < 100) usleep(10000);

            unset_filters(nmap, th_info->t_index);

            for (int i = 0; i < nmap->port_count; ++i) {
                if (nmap->hosts[th_info->h_index].port_states[th_info->current_scan][i] == PORT_UNDEFINED) {
                    nmap->hosts[th_info->h_index].port_states[th_info->current_scan][i] = default_port_state[th_info->current_scan];
                }
            }
            hostname_finished[th_info->t_index] = true;
        }
        if (run) print_scan_report(th_info);
    }
    sender_finished[th_info->t_index] = true;
    pcap_breakloop(handle_lo[th_info->t_index]);
    pcap_breakloop(handle_net[th_info->t_index]);
    pthread_join(capture_thread_lo, NULL);
    pthread_join(capture_thread_net, NULL);
    return NULL;
}
