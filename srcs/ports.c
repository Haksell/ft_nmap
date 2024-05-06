#include "ft_nmap.h"

bool get_port(uint64_t* ports, uint16_t port) {
    uint16_t page = port >> 6;
    uint16_t index = port & 63;

    return (ports[page] >> index) & 1;
}

void set_port(t_nmap* nmap, uint16_t port) {
    static bool warning = false;
    uint16_t page = port >> 6;
    uint16_t index = port & 63;

    if (!get_port(nmap->port_set, port) && ++nmap->port_count > MAX_PORTS) {
        panic("The number of specified ports exceeds the maximum limit of %d.\n", MAX_PORTS);
    }

    if (!warning && (nmap->port_set[page] >> index) & 1) {
        warning = true;
        fprintf(
            stderr,
            "WARNING: Duplicate port number(s) specified.  "
            "Are you alert enough to be using nmap?  "
            "Have some coffee or Jolt(tm).\n"
        );
    }

    nmap->port_set[page] |= 1ull << index;
}

void set_default_port_states(t_thread_info* th_info) {
    t_nmap* nmap = th_info->nmap;
    for (int i = 0; i < nmap->port_count; ++i) {
        if (nmap->hosts[th_info->h_index].port_states[th_info->current_scan][i] == PORT_UNDEFINED) {
            nmap->hosts[th_info->h_index]
                .port_states[th_info->current_scan][i] = default_port_state[th_info->current_scan];
        }
    }
}
