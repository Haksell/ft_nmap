#include "ft_nmap.h"
#include "udp_probes.h"

extern volatile sig_atomic_t run;
extern pthread_mutex_t mutex_run;

static void get_udp_probe(t_thread_info* th_info, uint16_t port) {
    bool already_sent_payload = false;
    for (size_t i = 0; udp_probes[i].rarity != SENTINEL_RARITY; ++i) {
        t_probe probe = udp_probes[i];
        size_t start = probe.port_ranges_start << 1;
        size_t end = probe.port_ranges_end << 1;
        for (size_t j = start; j < end; j += 2) {
            if (concatenated_port_ranges[j] <= port && port <= concatenated_port_ranges[j + 1]) {
                if (already_sent_payload) usleep(1000000);
                already_sent_payload = true;
                size_t payload_size = probe.payload_end - probe.payload_start;
                uint8_t packet[sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size];
                fill_packet(th_info, packet, port, concatenated_payloads + probe.payload_start, payload_size);
                sendto(
                    th_info->nmap->udp_fd,
                    packet,
                    sizeof(packet),
                    0,
                    (struct sockaddr*)&th_info->hostaddr,
                    sizeof(th_info->hostaddr)
                );
                break;
            }
        }
    }
    if (!already_sent_payload) {
        uint8_t packet[sizeof(struct iphdr) + sizeof(struct udphdr)];
        fill_packet(th_info, packet, port, concatenated_payloads, 0);
        sendto(
            th_info->nmap->udp_fd,
            packet,
            sizeof(packet),
            0,
            (struct sockaddr*)&th_info->hostaddr,
            sizeof(th_info->hostaddr)
        );
    }
}

static void send_udp(t_thread_info* th_info, uint16_t port) { get_udp_probe(th_info, port); }

static void send_packet(t_thread_info* th_info, uint16_t port) {
    if (th_info->current_scan == SCAN_UDP) send_udp(th_info, port);
    else {
        // TODO: send_tcp
        uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
        fill_packet(th_info, packet, port, NULL, 0);
        sendto(
            th_info->nmap->tcp_fd,
            packet,
            sizeof(packet),
            0,
            (struct sockaddr*)&th_info->hostaddr,
            sizeof(th_info->hostaddr)
        );
    }
}

static bool is_host_down(t_thread_info* th_info) { // TODO: use the brain
    t_nmap* nmap = th_info->nmap;
    uint8_t buffer[64] = {0}; //  a refaire avec socket a partir de l'autre thread
    int bytes_received = recv(nmap->icmp_fd, buffer, sizeof(buffer), 0);
    if (bytes_received < 0 && errno != EWOULDBLOCK && errno != EAGAIN && errno != EINTR) error("recv failed");
    return bytes_received <= 0;
}

static pthread_t create_capture_thread(t_capture_args* args) {
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, capture_packets, args)) panic("Failed to create the capture thread");
    return thread_id;
}

static void print_host_is_down(t_thread_info* th_info) {
    t_nmap* nmap = th_info->nmap;
    pthread_mutex_lock(&nmap->mutex_print);
    printf("\nHost %s is down.\n", nmap->hosts[th_info->h_index].name);
    pthread_mutex_unlock(&nmap->mutex_print);
}

void* send_packets(void* arg) {
    t_thread_info* th_info = arg;
    t_nmap* nmap = th_info->nmap;
    const int wait_operations = 10 + (nmap->port_count / 50);
    uint16_t* loop_port_array = nmap->opt & OPT_NO_RANDOMIZE ? nmap->port_array : nmap->random_port_array;

    pthread_t capture_thread_lo = create_capture_thread(&(t_capture_args){
        .th_info = th_info,
        .handle = th_info->globals.handle_lo,
    });
    pthread_t capture_thread_net = create_capture_thread(&(t_capture_args){
        .th_info = th_info,
        .handle = th_info->globals.handle_net,
    });

    int step = nmap->num_threads == 0 ? 1 : nmap->num_threads;

    for (th_info->h_index = th_info->t_index; th_info->h_index < nmap->hostname_count && run;
         th_info->h_index += step) {
        if (!hostname_to_ip(th_info->nmap->hosts[th_info->h_index].name, th_info->hostip)) continue;
        th_info->latency = 0.0;
        th_info->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(th_info->hostip)};
        bool is_localhost = (th_info->hostaddr.sin_addr.s_addr & 255) == 127;
        th_info->globals.current_handle = is_localhost ? th_info->globals.handle_lo : th_info->globals.handle_net;
        if (!(nmap->opt & OPT_NO_PING) && !is_localhost) {
            set_filter(th_info, true);
            send_ping(th_info);
            if (is_host_down(th_info) && run) {
                print_host_is_down(th_info);
                continue;
            }
            unset_filters(nmap, th_info->t_index);
        }

        for (scan_type scan = 0; scan < SCAN_MAX && run; ++scan) {
            if ((nmap->scans & (1 << scan)) == 0) continue;
            pthread_mutex_lock(&mutex_run);
            th_info->current_scan = scan;
            pthread_mutex_unlock(&mutex_run);
            if (scan == SCAN_CONN) {
                scan_connect(th_info, loop_port_array);
                continue;
            }

            th_info->port_source = random_u32_range(1 << 15, UINT16_MAX - MAX_PORTS);
            set_filter(th_info, false);

            // TODO: --transmissions flag
            for (int transmission = 0; transmission < 2; ++transmission) {
                for (int port_index = 0; port_index < nmap->port_count && run; ++port_index) {
                    if (nmap->hosts[th_info->h_index].port_states[th_info->current_scan][port_index] != PORT_UNDEFINED)
                        continue;
                    if (th_info->current_scan == SCAN_UDP && (port_index > 6 || transmission > 0)) usleep(1000000);
                    send_packet(th_info, loop_port_array[port_index]);
                }

                for (int i = 0; i < wait_operations && run; ++i) {
                    pthread_mutex_lock(&nmap->mutex_undefined_count);
                    bool zero = nmap->hosts[th_info->h_index].undefined_count[th_info->current_scan] == 0;
                    pthread_mutex_unlock(&nmap->mutex_undefined_count);
                    if (zero) break;
                    usleep(50000);
                }
            }

            unset_filters(nmap, th_info->t_index);
            set_default_port_states(th_info);
            pthread_mutex_lock(&nmap->mutex_hostname_finished);
            th_info->globals.hostname_finished = true;
            pthread_mutex_unlock(&nmap->mutex_hostname_finished);
        }
        if (run) {
            if (nmap->hosts[th_info->h_index].is_up || (nmap->opt & OPT_NO_PING)) print_scan_report(th_info);
            else print_host_is_down(th_info);
        }
    }
    pthread_mutex_lock(&mutex_run);
    th_info->globals.sender_finished = true;
    pthread_mutex_unlock(&mutex_run);

    pcap_breakloop(th_info->globals.handle_lo);
    pcap_breakloop(th_info->globals.handle_net);
    pthread_join(capture_thread_lo, NULL);
    pthread_join(capture_thread_net, NULL);
    return NULL;
}
