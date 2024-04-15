#include "ft_nmap.h"

void print_hostnames(t_nmap* nmap) {
    printf("Hosts: ");
    for (int i = 0; i < nmap->hostname_count; ++i) printf(i == 0 ? "%s" : ", %s", nmap->hostnames[i]);
    printf("\n");
}

void print_ports(t_nmap* nmap, char* name, uint16_t* port_array) {
    printf("%s: ", name);
    for (int i = 0; i < nmap->port_count; ++i) printf(i == 0 ? "%d" : ",%d", port_array[i]);
    printf("\n");
}

void print_scans(uint8_t scans) {
    bool is_first_scan = true;
    printf("Scans: ");
    for (int i = 0; i < SCAN_MAX; ++i) {
        if (scans & (1 << i)) {
            printf(is_first_scan ? "%s" : ",%s", scans_str[i]);
            is_first_scan = false;
        }
    }
    printf("\n");
}
