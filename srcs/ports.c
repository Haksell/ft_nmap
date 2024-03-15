#include "ft_nmap.h"

bool get_port(uint64_t* ports, uint16_t port) {
    uint16_t page = port >> 6;
    uint16_t index = port & 63;

    return (ports[page] >> index) & 1;
}

void set_port(uint64_t* ports, uint16_t port) {
    static bool warning = false;
    static int total_ports = 0;
    uint16_t page = port >> 6;
    uint16_t index = port & 63;

    if (!get_port(ports, port) && ++total_ports > MAX_PORTS) {
        fprintf(
            stderr, "The number of specified ports exceeds the maximum limit of %d.\n", MAX_PORTS
        );
        exit(EXIT_FAILURE);
    }

    if (!warning && (ports[page] >> index) & 1) {
        warning = true;
        fprintf(
            stderr,
            "WARNING: Duplicate port number(s) specified.  "
            "Are you alert enough to be using Nmap?  "
            "Have some coffee or Jolt(tm).\n"
        );
    }

    ports[page] |= 1ull << index;
}