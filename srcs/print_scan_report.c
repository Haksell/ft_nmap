#include "ft_nmap.h"

#define SEPARATOR " | "
#define MAX_SERVICE_LEN 32
#define HIDE_LIMIT 25 // TODO: Lorenzo flag?
#define HEADER_LINE (-1)
#define HIDE_LINE (-2)

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

static void copy_port_state_combination(t_nmap* nmap, port_state combination[SCAN_MAX], int port_index) {
    for (int scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
        combination[scan_type] = nmap->hosts[nmap->h_index].port_states[scan_type][port_index];
    }
}

static bool same_port_combination(t_nmap* nmap, port_state combination[SCAN_MAX], int port_index) {
    for (int scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
        if (combination[scan_type] != nmap->hosts[nmap->h_index].port_states[scan_type][port_index]) {
            return false;
        }
    }
    return true;
}

static t_paddings compute_paddings(t_nmap* nmap, int hide_count, port_state common_port_state_combination[SCAN_MAX]) {
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
            port_state state = nmap->hosts[nmap->h_index].port_states[scan_type][port_index];
            paddings.port_states[scan_type] = MAX(paddings.port_states[scan_type], port_state_info[state].strlen);
        }
        char tcp_service[MAX_SERVICE_LEN + 1];
        char udp_service[MAX_SERVICE_LEN + 1];
        get_service_name(port, "tcp", tcp_service);
        get_service_name(port, "udp", udp_service);
        if (hide_count == 0 || !same_port_combination(nmap, common_port_state_combination, port_index)) {
            paddings.tcp_service = MAX(paddings.tcp_service, strlen(tcp_service));
            paddings.udp_service = MAX(paddings.udp_service, strlen(udp_service));
        }
        if (!paddings.two_columns && strcmp(tcp_service, udp_service) != 0) paddings.two_columns = true;
    }
    bool has_tcp = nmap->scans & ~(1 << SCAN_UDP);
    bool has_udp = nmap->scans & (1 << SCAN_UDP);
    if (!has_tcp || !has_udp) paddings.two_columns = false;
    return paddings;
}

static int find_most_common_port_state_combination(t_nmap* nmap, port_state combination[SCAN_MAX]) {
    int counter = 1;
    copy_port_state_combination(nmap, combination, 0);
    for (int port_index = 1; port_index < nmap->port_count; ++port_index) {
        bool same = same_port_combination(nmap, combination, port_index);
        if (same) ++counter;
        else if (counter > 0) --counter;
        else {
            counter = 1;
            copy_port_state_combination(nmap, combination, port_index);
        }
    }
    counter = 0;
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        counter += same_port_combination(nmap, combination, port_index);
    }
    return counter >= HIDE_LIMIT && 2 * counter > nmap->port_count ? counter : 0;
}

static void print_scan_cell(
    t_nmap* nmap,
    t_paddings* paddings,
    scan_type scan_type,
    int port_index,
    int port,
    port_state common_port_state_combination[SCAN_MAX]
) {
    port_state port_state = port == HEADER_LINE ? PORT_UNDEFINED
                            : port == HIDE_LINE ? common_port_state_combination[scan_type]
                                                : nmap->hosts[nmap->h_index].port_states[scan_type][port_index];
    printf(
        "%s%-*s " WHITE,
        port == HEADER_LINE ? WHITE : port_state_info[port_state].color,
        paddings->port_states[scan_type],
        port == HEADER_LINE ? scans_str[scan_type] : port_state_info[port_state].str
    );
}

static void print_line(
    t_nmap* nmap,
    t_paddings* paddings,
    bool hide_count,
    port_state common_port_state_combination[SCAN_MAX],
    int port_index,
    int port,
    char* tcp_service,
    char* udp_service
) {
    if (port >= 0 && hide_count && same_port_combination(nmap, common_port_state_combination, port_index)) return;

    bool has_udp = (nmap->scans >> SCAN_UDP) & 1;

    if (port == HEADER_LINE) printf("%-*s", paddings->port, "PORT");
    else if (port == HIDE_LINE) printf("%-*s", paddings->port, "...");
    else printf("%-*d", paddings->port, port);

    if (!paddings->two_columns)
        printf(" %-*s", has_udp ? paddings->udp_service : paddings->tcp_service, has_udp ? udp_service : tcp_service);
    printf(nmap->scan_count >= 2 ? SEPARATOR : " ");

    for (int scan_type = 0; scan_type < SCAN_UDP; ++scan_type) {
        if (nmap->scans & (1 << scan_type)) {
            print_scan_cell(nmap, paddings, scan_type, port_index, port, common_port_state_combination);
        }
    }
    if (paddings->two_columns) printf("  %-*s" SEPARATOR, paddings->tcp_service, tcp_service);

    if (has_udp) {
        print_scan_cell(nmap, paddings, SCAN_UDP, port_index, port, common_port_state_combination);
        if (paddings->two_columns) printf("  %-*s", paddings->udp_service, udp_service);
    }
    printf("\n");
}

static void print_port_states(t_nmap* nmap) {
    port_state common_port_state_combination[SCAN_MAX];
    int hide_count = find_most_common_port_state_combination(nmap, common_port_state_combination);
    t_paddings paddings = compute_paddings(nmap, hide_count, common_port_state_combination);
    print_line(
        nmap,
        &paddings,
        hide_count,
        common_port_state_combination,
        HEADER_LINE,
        HEADER_LINE,
        "SERVICE",
        "SERVICE"
    );
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];

        char tcp_service[MAX_SERVICE_LEN + 1];
        char udp_service[MAX_SERVICE_LEN + 1];
        get_service_name(port, "tcp", tcp_service);
        get_service_name(port, "udp", udp_service);
        print_line(
            nmap,
            &paddings,
            hide_count,
            common_port_state_combination,
            port_index,
            port,
            tcp_service,
            udp_service
        );
    }
    if (hide_count) {
        print_line(nmap, &paddings, hide_count, common_port_state_combination, HIDE_LINE, HIDE_LINE, "", "");
        printf("Not shown: %d ports\n", hide_count);
    }
    printf(RESET);
}

void print_scan_report(t_nmap* nmap) {
    printf("\nNmap scan report for %s (%s)\n", nmap->hosts[nmap->h_index].name, nmap->hostip);
    double uptime = nmap->latency.tv_sec + nmap->latency.tv_usec / 1000000.0;
    printf("Host is up (%.2gs latency).\n", uptime);

    char host[NI_MAXHOST];
    if (ip_to_hostname(nmap->hostaddr.sin_addr, host, sizeof(host)))
        printf("rDNS record for %s: %s\n", nmap->hosts[nmap->h_index].name, host); // TODO: don't display if same

    print_port_states(nmap);
}
