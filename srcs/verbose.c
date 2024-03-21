#include "ft_nmap.h"

void print_hostnames(t_nmap* nmap) {
    printf("Hosts: ");
    for (int i = 0; i < nmap->hostname_count; ++i) printf(i == 0 ? "%s" : ", %s", nmap->hostnames[i]);
    printf("\n");
}

void print_ports(uint64_t* ports) {
    bool is_first_port = true;
    printf("Ports: ");
    for (int port = 0; port <= UINT16_MAX; ++port) {
        if (get_port(ports, port)) {
            printf(is_first_port ? "%d" : ",%d", port);
            is_first_port = false;
        }
    }
    printf("\n");
}

void print_scans(uint8_t scans) {
    bool is_first_scan = true;
    printf("Scans: ");
    for (int i = 0; valid_scans[i].type; ++i) {
        if (scans & valid_scans[i].type) {
            printf(is_first_scan ? "%s" : ",%s", valid_scans[i].name);
            is_first_scan = false;
        }
    }
    printf("\n");
}
