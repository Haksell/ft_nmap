#include "ft_nmap.h"

extern sig_atomic_t run;
extern sig_atomic_t hostname_finished[MAX_HOSTNAMES];
extern sig_atomic_t sender_finished[MAX_HOSTNAMES];
extern pcap_t* handle_lo[MAX_HOSTNAMES];
extern pcap_t* handle_net[MAX_HOSTNAMES];
extern pcap_t* current_handle[MAX_HOSTNAMES];
extern pthread_mutex_t mutex_run;

static void connect_scan(t_thread_info* th_info, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) error("Connect socket creation failed");

    struct timeval tv = {.tv_usec = 50000}; // 100ms à voir || latency + 100ms ??
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv) < 0)
        perror("setsockopt SO_RCVTIMEO failed");
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char*)&tv, sizeof tv) < 0)
        perror("setsockopt SO_SNDTIMEO failed");

    struct sockaddr_in target = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = th_info->hostaddr.sin_addr};

    // TODO: filtered state if timeout
    if (connect(fd, (struct sockaddr*)&target, sizeof(target)) == 0) set_port_state(th_info, PORT_OPEN, port);
    else set_port_state(th_info, PORT_CLOSED, port);
    close(fd);
}

static bool find_port(const char* line, uint16_t _port) {
    char port[6] = {0};
    sprintf(port, "%d", _port);
    const char* match = strstr(line, port);
    size_t end = strlen(port);

    while (match) {
        if ((match == line || *(match - 1) == ' ' || *(match - 1) == ',') &&
            (match[end] == ',' || match[end] == ' ' || match[end] == '\n' || match[end] == '\0')) {
            return true;
        }
        match = strstr(match + 1, port);
    }
    return false;
}

static size_t get_udp_payload(uint16_t port, uint8_t* payload, size_t payload_max_size) {
    return 0; // TODO
    FILE* file = fopen("nmap-service-probes", "r");
    if (!file) error("Failed to open nmap-service-probes file");

    char line[2048];
    char prev_line[2048];
    char prev_prev_line[2048];
    bool found_payload = false;

    while (fgets(line, sizeof(line), file)) {
        if (strstr(line, "ports") && strstr(prev_prev_line, "Probe UDP") && find_port(line, port)) {
            found_payload = true;
            break;
        }
        strcpy(prev_prev_line, prev_line);
        strcpy(prev_line, line);
    }

    fclose(file);
    if (!found_payload) return 0;

    char* ptr = strchr(prev_prev_line, '|') + 1;
    size_t i = 0;
    while (i < payload_max_size && *ptr && *ptr != '|') {
        if (*ptr != '\\') {
            payload[i++] = *ptr;
            ptr++;
        } else if (*(ptr + 1) == 'x') {
            unsigned int value;
            sscanf(ptr + 2, "%02x", &value);
            payload[i++] = (char)value;
            ptr += 4;
        } else {
            ptr++;
            switch (*ptr) {
                case '0': payload[i++] = '\0'; break;
                case 'r': payload[i++] = '\r'; break;
                case 'n': payload[i++] = '\n'; break;
                case 't': payload[i++] = '\t'; break;
                case 's': payload[i++] = ' '; break;
                default: payload[i++] = *ptr; break;
            }
            ptr++;
        }
    }
    return i;
}

static void send_packet(t_thread_info* th_info, uint16_t port) {
    t_nmap* nmap = th_info->nmap;

    if (th_info->current_scan == SCAN_CONNECT) {
        connect_scan(th_info, port);
    } else if (th_info->current_scan == SCAN_UDP) {
        uint8_t payload[1024] = {0};
        size_t payload_size = get_udp_payload(port, payload, sizeof(payload));
        uint8_t packet[sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size];
        fill_packet(th_info, packet, port, payload, payload_size);
        sendto(
            nmap->udp_fd,
            packet,
            sizeof(packet),
            0,
            (struct sockaddr*)&th_info->hostaddr,
            sizeof(th_info->hostaddr)
        );
    } else {
        uint8_t packet[sizeof(struct iphdr) + sizeof(struct tcphdr)];
        fill_packet(th_info, packet, port, NULL, 0);
        sendto(
            nmap->tcp_fd,
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
    if (bytes_received < 0 && errno != EWOULDBLOCK && errno != EAGAIN) error("recv failed");
    return bytes_received <= 0;
}

static pthread_t create_capture_thread(t_capture_args* args) {
    pthread_t thread_id;
    if (pthread_create(&thread_id, NULL, capture_packets, args)) panic("Failed to create the capture thread");
    return thread_id;
}

static void print_host_is_down(t_thread_info* th_info) {
    t_nmap* nmap = th_info->nmap;
    pthread_mutex_lock(&nmap->mutex_print_report);
    printf("\nHost %s is down.\n", nmap->hosts[th_info->h_index].name);
    pthread_mutex_unlock(&nmap->mutex_print_report);
}

void* send_packets(void* arg) {
    t_thread_info* th_info = arg;
    t_nmap* nmap = th_info->nmap;
    const int wait_operations = 10 + (nmap->port_count / 50);
    uint16_t* loop_port_array = nmap->opt & OPT_NO_RANDOMIZE ? nmap->port_array : nmap->random_port_array;

    // TODO: very important
    pthread_t capture_thread_lo = create_capture_thread(&(t_capture_args
    ){.th_info = th_info, .handle = handle_lo[th_info->t_index]});
    pthread_t capture_thread_net = create_capture_thread(&(t_capture_args
    ){.th_info = th_info, .handle = handle_net[th_info->t_index]});

    int step = nmap->num_threads == 0 ? 1 : nmap->num_threads;
    for (th_info->h_index = th_info->t_index; th_info->h_index < nmap->hostname_count && run;
         th_info->h_index += step) {
        if (!hostname_to_ip(th_info->nmap->hosts[th_info->h_index].name, th_info->hostip)) continue;
        th_info->latency = 0.0;
        th_info->hostaddr = (struct sockaddr_in){.sin_family = AF_INET, .sin_addr.s_addr = inet_addr(th_info->hostip)};
        bool is_localhost = (th_info->hostaddr.sin_addr.s_addr & 255) == 127;
        current_handle[th_info->t_index] = is_localhost ? handle_lo[th_info->t_index] : handle_net[th_info->t_index];
        if (!(nmap->opt & OPT_NO_PING) && !is_localhost) {
            set_filter(th_info, true);
            send_ping(th_info);
            if (is_host_down(th_info)) {
                print_host_is_down(th_info);
                continue;
            }
            unset_filters(nmap, th_info->t_index);
        }

        for (scan_type scan = 0; scan < SCAN_MAX && run; ++scan) {
            if ((nmap->scans & 1 << scan) == 0) continue;
            pthread_mutex_lock(&mutex_run);
            th_info->current_scan = scan;
            pthread_mutex_unlock(&mutex_run);
            th_info->port_source = random_u32_range(1 << 15, UINT16_MAX - MAX_PORTS);
            set_filter(th_info, false);
            for (int port_index = 0; port_index < nmap->port_count && run; ++port_index) {
                if (th_info->current_scan == SCAN_UDP && port_index > 6) usleep(1000000);
                send_packet(th_info, loop_port_array[port_index]);
            }

            for (int i = 0; i < wait_operations && run; ++i) {
                pthread_mutex_lock(&nmap->mutex_undefined_count);
                bool zero = nmap->hosts[th_info->h_index].undefined_count[th_info->current_scan] == 0;
                pthread_mutex_unlock(&nmap->mutex_undefined_count);
                if (zero) break;
                usleep(50000);
            }

            unset_filters(nmap, th_info->t_index);

            for (int i = 0; i < nmap->port_count; ++i) {
                if (nmap->hosts[th_info->h_index].port_states[th_info->current_scan][i] == PORT_UNDEFINED) {
                    nmap->hosts[th_info->h_index]
                        .port_states[th_info->current_scan][i] = default_port_state[th_info->current_scan];
                }
            }
            pthread_mutex_lock(&nmap->mutex_hostname_finished); // TODO ON VERRA
            hostname_finished[th_info->t_index] = true;
            pthread_mutex_unlock(&nmap->mutex_hostname_finished);
        }
        if (run) {
            if (nmap->hosts[th_info->h_index].is_up) print_scan_report(th_info);
            else print_host_is_down(th_info);
        }
    }
    pthread_mutex_lock(&mutex_run);
    sender_finished[th_info->t_index] = true;
    pthread_mutex_unlock(&mutex_run);

    pcap_breakloop(handle_lo[th_info->t_index]);
    pcap_breakloop(handle_net[th_info->t_index]);
    pthread_join(capture_thread_lo, NULL);
    pthread_join(capture_thread_net, NULL);
    return NULL;
}
