#include "ft_nmap.h"

#define SHOW_LIMIT 25

extern bool run;

static void print_port_states(t_nmap* nmap) {
    int open = 0, closed = 0, filtered = 0; // TODO: other states except open

    for (int j = 0; j < nmap->port_count; ++j) {
        port_state state = nmap->port_states[nmap->hostname_index][0][j];
        open += state == PORT_OPEN;
        closed += state == PORT_CLOSED;
        filtered += state == PORT_FILTERED;
    }

    if (open == 0 && filtered == 0 && closed > SHOW_LIMIT)
        printf(
            "All %d scanned ports on %s (%s) are in ignored states.\n",
            nmap->port_count,
            nmap->hostnames[nmap->hostname_index],
            nmap->hostip
        ); // TODO: Lorenzo
    if (closed > SHOW_LIMIT) printf("Not shown: %d closed tcp ports (reset)\n", closed); // TODO: not tcp and reset
    if (filtered > SHOW_LIMIT) printf("Not shown: %d filtered tcp ports (no-response)\n", filtered);
    if (open == 0 && closed > SHOW_LIMIT && (filtered == 0 || filtered > SHOW_LIMIT)) return;

    struct servent* service;
    printf("PORT   STATE SERVICE\n"); // TODO: Axel align styleeeeee'
    for (int j = 0; j < nmap->port_count; ++j) {
        port_state state = nmap->port_states[nmap->hostname_index][0][j];
        if (state == PORT_OPEN || (state == PORT_CLOSED && closed <= SHOW_LIMIT) ||
            (state == PORT_FILTERED && filtered <= SHOW_LIMIT)) {
            service = getservbyport(htons(nmap->port_array[j]), "tcp");
            port_state port_state = nmap->port_states[nmap->hostname_index][0][j];
            if (port_state == PORT_FILTERED && filtered > SHOW_LIMIT) continue;
            if (port_state == PORT_CLOSED && closed > SHOW_LIMIT) continue;

            printf(
                "%d/tcp %s  %s\n",
                nmap->port_array[j],
                port_state_str[port_state],
                service ? service->s_name : "unknown"
            );
        }
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
            while (nmap->undefined_count[nmap->hostname_index] > 0) usleep(1000); // TODO: no forbidden functions
            alarm(0);
        }
        print_scan_report(nmap);
    }
    handle_sigint(SIGINT);
    return NULL;
}
