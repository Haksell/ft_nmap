#include "ft_nmap.h"

// SHOW_LIMIT: https://github.com/Haksell/ft_nmap/blob/3825e0fd2b2909f20c425ce91910ee32788bc7b2/srcs/send_packets.c

// TODO: put display code in display file

extern bool run;

#define SEPARATOR " | "

typedef struct {
    int port;
    int port_states[SCAN_MAX];
    int tcp_service;
    int udp_service;
} t_paddings;

static char* get_service_name(uint16_t port, const char* proto) {
    struct servent* service = getservbyport(htons(port), proto);
    return service ? service->s_name : "unknown";
}

static t_paddings compute_paddings(t_nmap* nmap) {
    // TODO: macros Lorenzo
    t_paddings paddings = {
        .port = 4,
        .port_states = {3, 3, 4, 3, 4, 3},
        .tcp_service = 7,
        .udp_service = 7
    };
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];
        if (port >= 10000) paddings.port = 5;
        for (int scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
            port_state state = nmap->port_states[nmap->hostname_index][scan_type][port_index];
            paddings.port_states[scan_type] = MAX(paddings.port_states[scan_type], port_state_strlen[state]);
        }
        paddings.tcp_service = MAX(paddings.tcp_service, strlen(get_service_name(port, "tcp")));
        paddings.udp_service = MAX(paddings.udp_service, strlen(get_service_name(port, "udp")));
    }
    return paddings;
}

static void print_scan_cell(t_nmap* nmap, t_paddings* paddings, scan_type scan_type, int port_index, int port) {
    printf(
        "%-*s ",
        paddings->port_states[scan_type],
        port >= 0 ? port_state_str[nmap->port_states[nmap->hostname_index][scan_type][port_index]]
                  : scans_str[scan_type]
    );
}

static void
print_line(t_nmap* nmap, t_paddings* paddings, int port_index, int port, char* tcp_service, char* udp_service) {
    if (port >= 0) printf("%-*d", paddings->port, port);
    else printf("%-*s", paddings->port, "PORT");

    printf(SEPARATOR);

    for (int scan_type = 0; scan_type < SCAN_UDP; ++scan_type) {
        if ((nmap->scans & (1 << scan_type))) {
            print_scan_cell(nmap, paddings, scan_type, port_index, port);
        }
    }

    bool has_tcp = nmap->scans & ~(1 << SCAN_UDP);
    bool has_udp = nmap->scans & (1 << SCAN_UDP);
    if (has_tcp) printf("  %-*s", paddings->tcp_service, tcp_service);
    if (has_tcp && has_udp) printf(SEPARATOR);
    if (has_udp) {
        print_scan_cell(nmap, paddings, SCAN_UDP, port_index, port);
        printf("  %-*s", paddings->udp_service, udp_service);
    }
    printf("\n");
}

static void print_port_states(t_nmap* nmap) {
    t_paddings paddings = compute_paddings(nmap);
    print_line(nmap, &paddings, -1, -1, "SERVICE", "SERVICE");
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];
        print_line(nmap, &paddings, port_index, port, get_service_name(port, "tcp"), get_service_name(port, "udp"));
    }
}

static void print_scan_report(t_nmap* nmap) {
    printf("\nNmap scan report for %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
    double uptime = nmap->latency.tv_sec + nmap->latency.tv_usec / 1000000.0;
    printf("Host is up (%.2gs latency).\n", uptime);
    printf(
        "rDNS record for %s: fra15s10-in-f14.1e100.net\n\n", // TODO: only one \n sometimes
        nmap->hostnames[nmap->hostname_index]
    ); // TODO LORENZO DNS uniquement s'il a trouve le dns
    print_port_states(nmap);
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
            ); // a print uniquement si le seul host est down, donc pas ici
            continue;
        }

        for (int i = 0; i < SCAN_MAX; ++i) {
            nmap->current_scan = i;
            if ((nmap->scans & (1 << i)) == 0) continue;

            nmap->port_source = random_u32_range(1 << 15, UINT16_MAX);
            set_filter(nmap);
            // TODO: shuffle
            for (int j = 0; j < nmap->port_count && run; ++j) {
                uint16_t port = nmap->port_array[j];
                uint8_t packet[NMAP_PACKET_SIZE /*+data eventuellement*/];
                fill_packet(packet, nmap, port);
                sendto(
                    nmap->fd,
                    packet,
                    NMAP_PACKET_SIZE,
                    0,
                    (struct sockaddr*)&nmap->hostaddr,
                    sizeof(nmap->hostaddr)
                );
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
