#include "ft_nmap.h"
#include "udp_probes.h"

#define WAIT_SCAN_US 50000

extern volatile sig_atomic_t run;
extern pthread_mutex_t mutex_run;

static void send_udp_probe(t_thread_info* th_info, uint16_t port, t_probe probe) {
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
    // TODO: on verifier si tout est protege!!!!!
}

static void send_packet_udp(t_thread_info* th_info, uint16_t port) {
    bool already_sent_payload = false;
    for (size_t i = 0; udp_probes[i].rarity != SENTINEL_RARITY; ++i) {
        t_probe probe = udp_probes[i];
        size_t start = probe.port_ranges_start << 1;
        size_t end = probe.port_ranges_end << 1;
        for (size_t j = start; j < end; j += 2) {
            if (concatenated_port_ranges[j] <= port && port <= concatenated_port_ranges[j + 1]) {
                if (already_sent_payload) usleep(1000000); // TODO: multiplex
                already_sent_payload = true;
                send_udp_probe(th_info, port, probe);
                break;
            }
        }
    }
    if (!already_sent_payload) send_udp_probe(th_info, port, SENTINEL_PROBE);
}

static void send_packet_tcp(t_thread_info* th_info, uint16_t port) {
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
    // TODO: lsimanic t'as enleve' la protection
}

static pthread_t create_capture_thread(t_capture_args* args) {
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, capture_packets, args)) panic("Failed to create the capture thread");
    return thread_id;
}

static void exec_scan(t_thread_info* th_info, uint16_t* loop_port_array) {
    t_nmap* nmap = th_info->nmap;
    t_host* host = &nmap->hosts[th_info->h_index];
    // TODO: --retransmissions
    for (int transmission = 0; transmission < 3; ++transmission) {
        for (int port_index = 0; port_index < nmap->port_count && run; ++port_index) {
            if (host->port_states[th_info->current_scan][port_index] != PORT_UNDEFINED) continue;
            uint16_t port = loop_port_array[port_index];
            if (th_info->current_scan == SCAN_UDP && (port_index > 6 || transmission > 0)) usleep(1000000);
            (th_info->current_scan == SCAN_UDP ? send_packet_udp : send_packet_tcp)(th_info, port);
        }

        int latency_sleeps = th_info->latency ? (2 * th_info->latency) / WAIT_SCAN_US : 5;
        int port_sleeps = host->undefined_count[th_info->current_scan] * 500 / WAIT_SCAN_US;
        int sleeps = 1 + latency_sleeps + port_sleeps;

        for (int i = 0; i < sleeps && run; ++i) {
            pthread_mutex_lock(&nmap->mutex_undefined_count);
            bool zero = host->undefined_count[th_info->current_scan] == 0;
            pthread_mutex_unlock(&nmap->mutex_undefined_count);
            if (zero) return;
            usleep(WAIT_SCAN_US);
        }
    }
}

void* send_packets(void* arg) {
    t_thread_info* th_info = arg;
    t_nmap* nmap = th_info->nmap;
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
            set_filter(th_info, SCAN_MAX);
            send_ping(th_info);
        }

        for (scan_type scan = 0; scan < SCAN_MAX && run; ++scan) {
            if ((nmap->scans & (1 << scan)) == 0) continue;
            pthread_mutex_lock(&mutex_run);
            th_info->current_scan = scan;
            pthread_mutex_unlock(&mutex_run);
            if (scan == SCAN_CONN) {
                scan_connect(th_info, loop_port_array);
            } else {
                th_info->port_source = random_u32_range(1 << 15, UINT16_MAX - MAX_PORTS);
                set_filter(th_info, scan);
                exec_scan(th_info, loop_port_array);
                unset_filters(nmap, th_info->t_index);
                set_default_port_states(th_info);
            }
        }
        if (run) print_scan_report(th_info);
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
