#include "../ft_nmap.h"
#include <stdint.h>

bool get_port(uint64_t* ports, uint16_t port) {
    uint16_t page = port >> 6;
    uint16_t index = port & 63;

    return (ports[page] >> index) & 1;
}

void set_port(uint64_t* ports, uint16_t port) {
    static bool warning = false;
    uint16_t page = port >> 6;
    uint16_t index = port & 63;

    if (!warning && (ports[page] >> index) & 1) {
        warning = true;
        fprintf(stderr, "WARNING: Duplicate port number(s) specified.  Are you alert enough to be using Nmap?  Have some coffee or Jolt(tm).");
    }
    ports[page] |= 1 << index;
}