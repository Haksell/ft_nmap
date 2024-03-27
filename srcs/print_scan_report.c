#include "ft_nmap.h"

// SHOW_LIMIT: https://github.com/Haksell/ft_nmap/blob/3825e0fd2b2909f20c425ce91910ee32788bc7b2/srcs/send_packets.c
// si tu te fais chier, tu peux faire un truc pour ne pas afficher plus de 25 closes ports, 25 filtered ports, etc.
// mais pas du tout urgent

#define SEPARATOR " | "
#define SERVICE_BUFFER_SIZE 32

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
            paddings.port_states[scan_type] = MAX(paddings.port_states[scan_type], port_state_info[state].strlen);
        }
        paddings.tcp_service = MAX(paddings.tcp_service, strlen(get_service_name(port, "tcp")));
        paddings.udp_service = MAX(paddings.udp_service, strlen(get_service_name(port, "udp")));
    }
    return paddings;
}

static void print_scan_cell(t_nmap* nmap, t_paddings* paddings, scan_type scan_type, int port_index, int port) {
    port_state port_state = port >= 0 ? nmap->port_states[nmap->hostname_index][scan_type][port_index] : PORT_UNDEFINED;
    printf(
        "%s%-*s " WHITE,
        port >= 0 ? port_state_info[port_state].color : WHITE,
        paddings->port_states[scan_type],
        port >= 0 ? port_state_info[port_state].str : scans_str[scan_type]
    );
}

static void print_line(
    t_nmap* nmap,
    t_paddings* paddings,
    bool hide_unresponsive,
    int port_index,
    int port,
    char* tcp_service,
    char* udp_service
) {
    if (port >= 0 && hide_unresponsive && !nmap->is_responsive[nmap->hostname_index][port_index]) return;

    if (port >= 0) printf("%-*d", paddings->port, port);
    else printf("%-*s", paddings->port, "PORT");

    printf(SEPARATOR);

    for (int scan_type = 0; scan_type < SCAN_UDP; ++scan_type) {
        if (nmap->scans & (1 << scan_type)) {
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

#define SHOW_LIMIT 1000 // TODO: en haut

static void print_port_states(t_nmap* nmap) {
    uint16_t unresponsive_count = nmap->port_count - nmap->responsive_count[nmap->hostname_index];
    bool hide_unresponsive = unresponsive_count > SHOW_LIMIT;
    if (hide_unresponsive) printf("Not shown: %d unresponsive ports\n", unresponsive_count);
    printf("\n");
    t_paddings paddings = compute_paddings(nmap);
    print_line(nmap, &paddings, hide_unresponsive, -1, -1, "SERVICE", "SERVICE");
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];

        char tcp_service[SERVICE_BUFFER_SIZE];
        char udp_service[SERVICE_BUFFER_SIZE];
        strncpy(tcp_service, get_service_name(port, "tcp"), SERVICE_BUFFER_SIZE);
        strncpy(udp_service, get_service_name(port, "udp"), SERVICE_BUFFER_SIZE);
        print_line(nmap, &paddings, hide_unresponsive, port_index, port, tcp_service, udp_service);
    }
    printf(RESET);
}

void print_scan_report(t_nmap* nmap) {
    printf("\nNmap scan report for %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
    double uptime = nmap->latency.tv_sec + nmap->latency.tv_usec / 1000000.0;
    printf("Host is up (%.2gs latency).\n", uptime);
    printf(
        "rDNS record for %s: fra15s10-in-f14.1e100.net\n",
        nmap->hostnames[nmap->hostname_index]
    ); // TODO LORENZO DNS uniquement s'il a trouve le dns
    print_port_states(nmap);
}
