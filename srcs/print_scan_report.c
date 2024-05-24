#include "ft_nmap.h"

#define SEPARATOR " | "
#define HIDE_LIMIT 10
#define HEADER_LINE (-1)
#define HIDE_LINE (-2)

typedef struct {
    int port;
    int port_states[SCAN_MAX];
    int tcp_service;
    int udp_service;
    bool two_columns;
} t_paddings;

static void copy_port_state_combination(t_thread_info* th_info, t_port_state combination[SCAN_MAX], int port_index) {
    for (t_scan_type scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
        combination[scan_type] = th_info->host->port_states[scan_type][port_index];
    }
}

static bool same_port_combination(t_thread_info* th_info, t_port_state combination[SCAN_MAX], int port_index) {
    for (t_scan_type scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
        if (combination[scan_type] != th_info->host->port_states[scan_type][port_index]) {
            return false;
        }
    }
    return true;
}

static t_paddings
compute_paddings(t_thread_info* th_info, int hide_count, t_port_state common_port_state_combination[SCAN_MAX]) {
    t_nmap* nmap = th_info->nmap;
    t_paddings paddings = {
        .port = 4,
        .port_states = {3, 3, 4, 3, 4, 3},
        .tcp_service = 7,
        .udp_service = 7,
        .two_columns = false
    };
    bool may_have_two_columns = (nmap->scans & ~(1 << SCAN_UDP)) && (nmap->scans & (1 << SCAN_UDP));
    for (int port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];
        if (port >= 10000) paddings.port = 5;
        for (t_scan_type scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
            t_port_state state = th_info->host->port_states[scan_type][port_index];
            paddings.port_states[scan_type] = MAX(paddings.port_states[scan_type], port_state_info[state].strlen);
        }
        if (hide_count == 0 || !same_port_combination(th_info, common_port_state_combination, port_index)) {
            char* tcp_service = nmap->tcp_services[port_index];
            char* udp_service = nmap->udp_services[port_index];
            paddings.tcp_service = MAX(paddings.tcp_service, strlen(tcp_service));
            paddings.udp_service = MAX(paddings.udp_service, strlen(udp_service));
            if (may_have_two_columns && !paddings.two_columns && strcmp(tcp_service, udp_service) != 0)
                paddings.two_columns = true;
        }
    };
    return paddings;
}

static int find_most_common_port_state_combination(t_thread_info* th_info, t_port_state combination[SCAN_MAX]) {
    uint16_t port_count = th_info->nmap->port_count;
    int counter = 1;
    copy_port_state_combination(th_info, combination, 0);
    for (int port_index = 1; port_index < port_count; ++port_index) {
        bool same = same_port_combination(th_info, combination, port_index);
        if (same) ++counter;
        else if (counter > 0) --counter;
        else {
            counter = 1;
            copy_port_state_combination(th_info, combination, port_index);
        }
    }
    counter = 0;
    for (int port_index = 0; port_index < port_count; ++port_index) {
        counter += same_port_combination(th_info, combination, port_index);
    }
    return counter >= HIDE_LIMIT && 2 * counter > port_count ? counter : 0;
}

static void print_scan_cell(
    t_thread_info* th_info,
    t_paddings* paddings,
    t_scan_type scan_type,
    int port_index,
    int port,
    t_port_state common_port_state_combination[SCAN_MAX]
) {
    t_port_state port_state = port == HEADER_LINE ? PORT_UNDEFINED
                              : port == HIDE_LINE ? common_port_state_combination[scan_type]
                                                  : th_info->host->port_states[scan_type][port_index];
    printf(
        "%s%-*s " WHITE,
        port == HEADER_LINE ? WHITE : port_state_info[port_state].color,
        paddings->port_states[scan_type],
        port == HEADER_LINE ? scans_str[scan_type] : port_state_info[port_state].str
    );
}

static void print_line(
    t_thread_info* th_info,
    t_paddings* paddings,
    t_port_state common_port_state_combination[SCAN_MAX],
    int port_index
) {
    t_nmap* nmap = th_info->nmap;
    int port = port_index < 0 ? port_index : nmap->port_array[port_index];
    bool has_udp = (nmap->scans >> SCAN_UDP) & 1;

    char* tcp_service = port == HIDE_LINE ? "" : port == HEADER_LINE ? "SERVICE" : nmap->tcp_services[port_index];
    char* udp_service = port == HIDE_LINE ? "" : port == HEADER_LINE ? "SERVICE" : nmap->udp_services[port_index];

    if (port == HEADER_LINE) printf("%-*s", paddings->port, "PORT");
    else if (port == HIDE_LINE) printf("%-*s", paddings->port, "...");
    else printf("%-*d", paddings->port, port);

    if (!paddings->two_columns)
        printf(" %-*s", has_udp ? paddings->udp_service : paddings->tcp_service, has_udp ? udp_service : tcp_service);
    printf(nmap->scan_count >= 2 ? SEPARATOR : " ");

    if (nmap->scans & (1 << SCAN_CONN))
        print_scan_cell(th_info, paddings, SCAN_CONN, port_index, port, common_port_state_combination);

    for (t_scan_type scan_type = 0; scan_type < SCAN_MAX; ++scan_type) {
        if (scan_type == SCAN_UDP || scan_type == SCAN_CONN) continue;
        if (nmap->scans & (1 << scan_type)) {
            print_scan_cell(th_info, paddings, scan_type, port_index, port, common_port_state_combination);
        }
    }
    if (paddings->two_columns) printf("  %-*s" SEPARATOR, paddings->tcp_service, tcp_service);

    if (has_udp) {
        print_scan_cell(th_info, paddings, SCAN_UDP, port_index, port, common_port_state_combination);
        if (paddings->two_columns) printf("  %-*s", paddings->udp_service, udp_service);
    }
    printf("\n");
}

static void gotta_go_fast(
    t_thread_info* th_info,
    t_paddings* paddings,
    int hide_count,
    t_port_state* common_port_state_combination,
    char* host
) {
    if (strcmp(th_info->host->name, th_info->host->hostip) == 0)
        printf("\nnmap scan report for %s\n", th_info->host->name);
    else printf("\nnmap scan report for %s (%s)\n", th_info->host->name, th_info->host->hostip);

    if (th_info->latency) printf("Host is up (%.2fms latency).\n", th_info->latency / 1000.0);
    if (host[0] != '\0') printf("rDNS record for %s: %s\n", th_info->host->name, host);

    print_line(th_info, paddings, common_port_state_combination, HEADER_LINE);
    for (int port_index = 0; port_index < th_info->nmap->port_count; ++port_index) {
        if (!hide_count || !same_port_combination(th_info, common_port_state_combination, port_index)) {
            print_line(th_info, paddings, common_port_state_combination, port_index);
        }
    }

    if (hide_count) {
        print_line(th_info, paddings, common_port_state_combination, HIDE_LINE);
        printf("Not shown: %d ports\n", hide_count);
    }
}

static void print_host_is_up(t_thread_info* th_info) {
    t_port_state common_port_state_combination[SCAN_MAX];
    int hide_count = find_most_common_port_state_combination(th_info, common_port_state_combination);
    t_paddings paddings = compute_paddings(th_info, hide_count, common_port_state_combination);

    char host[NI_MAXHOST];
    if (!ip_to_hostname(th_info->hostaddr.sin_addr, host, sizeof(host)) || strcmp(th_info->host->name, host) == 0)
        host[0] = '\0';

    pthread_mutex_lock(&th_info->nmap->mutex_print);
    gotta_go_fast(th_info, &paddings, hide_count, common_port_state_combination, host);
    printf(RESET);
    pthread_mutex_unlock(&th_info->nmap->mutex_print);
}

static void print_host_is_down(t_thread_info* th_info) {
    pthread_mutex_lock(&th_info->nmap->mutex_print);
    printf("\nHost %s is down.\n", th_info->host->name);
    pthread_mutex_unlock(&th_info->nmap->mutex_print);
}

static void print_sent_spoof(t_thread_info* th_info) {
    t_nmap* nmap = th_info->nmap;
    char hostip[INET_ADDRSTRLEN + 1];

    pthread_mutex_lock(&th_info->nmap->mutex_print);
    if (!inet_ntop(AF_INET, &nmap->source_address, hostip, INET_ADDRSTRLEN) ||
        strcmp(nmap->spoof_hostname, hostip) == 0) {
        printf("\nSent packets from %s to ", nmap->spoof_hostname);
    } else printf("\nSent packets from %s (%s) to ", nmap->spoof_hostname, hostip);
    if (strcmp(th_info->host->name, th_info->host->hostip) == 0) printf("%s\n", th_info->host->name);
    else printf("%s (%s)\n", th_info->host->name, th_info->host->hostip);
    pthread_mutex_unlock(&th_info->nmap->mutex_print);
}

void print_scan_report(t_thread_info* th_info) {
    if (th_info->nmap->opt & OPT_SPOOF_ADDRESS) print_sent_spoof(th_info);
    else if (th_info->host->is_up) print_host_is_up(th_info);
    else print_host_is_down(th_info);
}
