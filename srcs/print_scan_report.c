#include "ft_nmap.h"

// SHOW_LIMIT: https://github.com/Haksell/ft_nmap/blob/3825e0fd2b2909f20c425ce91910ee32788bc7b2/srcs/send_packets.c
// si tu te fais chier, tu peux faire un truc pour ne pas afficher plus de 25 closes ports, 25 filtered ports, etc.
// mais pas du tout urgent

#define SEPARATOR " | "
#define MAX_SERVICE_LEN 32

typedef struct {
    int port;
    int port_states[SCAN_MAX];
    int tcp_service;
    int udp_service;
    bool two_columns;
} t_paddings;

static void get_service_name(uint16_t port, const char* proto, char buffer[MAX_SERVICE_LEN + 1]) {
    struct servent* service = getservbyport(htons(port), proto);
    char* service_name = service ? service->s_name : "unknown";
    strncpy(buffer, service_name, MAX_SERVICE_LEN - 1);
}

static t_paddings compute_paddings(t_nmap* nmap) {
    t_paddings paddings = {
        .port = 4,
        .port_states = {3, 3, 4, 3, 4, 3},
        .tcp_service = 7,
        .udp_service = 7,
        .two_columns = false
    };
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];
        if (port >= 10000) paddings.port = 5;
        for (int scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
            port_state state = nmap->port_states[nmap->hostname_index][scan_type][port_index];
            paddings.port_states[scan_type] = MAX(paddings.port_states[scan_type], port_state_info[state].strlen);
        }
        char tcp_service[MAX_SERVICE_LEN + 1];
        char udp_service[MAX_SERVICE_LEN + 1];
        get_service_name(port, "tcp", tcp_service);
        get_service_name(port, "udp", udp_service);
        paddings.tcp_service = MAX(paddings.tcp_service, strlen(tcp_service));
        paddings.udp_service = MAX(paddings.udp_service, strlen(udp_service));
        if (!paddings.two_columns && strcmp(tcp_service, udp_service) != 0) paddings.two_columns = true;
    }
    bool has_tcp = nmap->scans & ~(1 << SCAN_UDP);
    bool has_udp = nmap->scans & (1 << SCAN_UDP);
    if (!has_tcp || !has_udp) paddings.two_columns = false;
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
    if (port >= 0 && hide_unresponsive && false) return;

    bool has_udp = (nmap->scans >> SCAN_UDP) & 1;

    if (port >= 0) printf("%-*d", paddings->port, port);
    else printf("%-*s", paddings->port, "PORT");
    if (!paddings->two_columns)
        printf(" %-*s", has_udp ? paddings->udp_service : paddings->tcp_service, has_udp ? udp_service : tcp_service);
    printf(nmap->scan_count >= 2 ? SEPARATOR : " ");

    for (int scan_type = 0; scan_type < SCAN_UDP; ++scan_type) {
        if (nmap->scans & (1 << scan_type)) {
            print_scan_cell(nmap, paddings, scan_type, port_index, port);
        }
    }
    if (paddings->two_columns) printf("  %-*s" SEPARATOR, paddings->tcp_service, tcp_service);

    if (has_udp) {
        print_scan_cell(nmap, paddings, SCAN_UDP, port_index, port);
        if (paddings->two_columns) printf("  %-*s", paddings->udp_service, udp_service);
    }
    printf("\n");
}

#define SHOW_LIMIT 10 // TODO: en haut

static void print_port_states(t_nmap* nmap) {
    uint16_t unresponsive_count = nmap->port_count - nmap->responsive_count[nmap->hostname_index];
    bool hide_unresponsive = unresponsive_count > SHOW_LIMIT;
    if (hide_unresponsive) printf("Not shown: %d unresponsive ports\n", unresponsive_count);
    printf("\n%d\n", unresponsive_count);
    t_paddings paddings = compute_paddings(nmap);
    print_line(nmap, &paddings, hide_unresponsive, -1, -1, "SERVICE", "SERVICE");
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];

        char tcp_service[MAX_SERVICE_LEN + 1];
        char udp_service[MAX_SERVICE_LEN + 1];
        get_service_name(port, "tcp", tcp_service);
        get_service_name(port, "udp", udp_service);
        print_line(nmap, &paddings, hide_unresponsive, port_index, port, tcp_service, udp_service);
    }
    printf(RESET);
}

void print_scan_report(t_nmap* nmap) {
    printf("\nNmap scan report for %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
    double uptime = nmap->latency.tv_sec + nmap->latency.tv_usec / 1000000.0;
    printf("Host is up (%.2gs latency).\n", uptime);

    char host[NI_MAXHOST];
    if (ip_to_hostname(nmap->hostaddr.sin_addr, host, sizeof(host)))
        printf("rDNS record for %s: %s\n", nmap->hostnames[nmap->hostname_index], host);

    print_port_states(nmap);
}
