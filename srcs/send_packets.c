#include "ft_nmap.h"

// SHOW_LIMIT: https://github.com/Haksell/ft_nmap/blob/3825e0fd2b2909f20c425ce91910ee32788bc7b2/srcs/send_packets.c

extern bool run;

static void show_port_state(t_nmap* nmap, uint16_t port, scan_type scan_type) {
    if (!(nmap->scans & (1 << scan_type))) return;
    port_state state = nmap->port_states[nmap->hostname_index][scan_type][port];
    printf("%-14s", port_state_str[state]);
}

static void print_port_states(t_nmap* nmap) {
    struct servent* service;
    printf("PORT\t");
    for (int scan_type = 0; scan_type < SCAN_UDP; ++scan_type) {
        if (!(nmap->scans & (1 << scan_type))) continue;
        printf("%-14s", valid_scans[scan_type].name);
    }
    bool has_tcp = nmap->scans & ~(1 << SCAN_UDP);
    bool has_udp = nmap->scans & (1 << SCAN_UDP);
    if (has_tcp) printf("%-14s", "SERVICE");
    if (has_udp) printf("    %-14s%-14s", "UDP", "SERVICE");
    printf("\n");
    for (int port = 0; port < nmap->port_count; ++port) {
        printf("%d\t", nmap->port_array[port]);
        for (int scan_type = 0; scan_type < SCAN_UDP; ++scan_type) show_port_state(nmap, port, scan_type);
        service = getservbyport(htons(nmap->port_array[port]), "tcp");
        if (has_tcp) printf("%-14s", service ? service->s_name : "unknown");
        if (has_udp) {
            printf("    ");
            show_port_state(nmap, port, SCAN_UDP);
            printf("%-14s", service ? service->s_name : "unknown");
        }
        printf("\n");
    }
}

static void print_scan_report(t_nmap* nmap) {
    printf("\nNmap scan report for %s (%s)\n", nmap->hostnames[nmap->hostname_index], nmap->hostip);
    double uptime = nmap->latency.tv_sec + nmap->latency.tv_usec / 1000000.0;
    printf("Host is up (%.2gs latency).\n", uptime);
    printf(
        "rDNS record for %s: fra15s10-in-f14.1e100.net\n",
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
