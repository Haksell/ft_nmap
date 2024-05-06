#include "ft_nmap.h"

#define PAYLOAD_LINE_WIDTH 16

static void print_hex_line(const u_char* payload, int len) {
    for (int i = 0; i < PAYLOAD_LINE_WIDTH; ++i) {
        if (i < len) printf("%02x ", *payload);
        else printf("   ");
        ++payload;
        if (i == 7) printf(" ");
    }
}

static void print_ascii_line(const u_char* payload, int len) {
    for (int i = 0; i < len; ++i) {
        printf("%c", isprint(*payload) ? *payload : '.');
        ++payload;
    }
}

static void print_hex_ascii_line(const u_char* payload, int len, int offset) {
    printf("%05x   ", offset);
    print_hex_line(payload, len);
    printf("   ");
    print_ascii_line(payload, len);
    printf("\n");
}

void print_payload(const u_char* payload, int size_payload) {
    printf("   Payload (%d bytes):\n", size_payload);
    for (int offset = 0; size_payload > 0; size_payload -= PAYLOAD_LINE_WIDTH) {
        print_hex_ascii_line(payload + offset, MIN(size_payload, PAYLOAD_LINE_WIDTH), offset);
        offset += PAYLOAD_LINE_WIDTH;
    }
}

void print_hostnames(t_nmap* nmap) {
    printf("Hosts: ");
    for (int i = 0; i < nmap->hostname_count; ++i) printf(i == 0 ? "%s" : ", %s", nmap->hosts[i].name);
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
