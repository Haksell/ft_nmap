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

void set_port_state(t_thread_info* th_info, t_port_state port_state, uint16_t port) {
    t_nmap* nmap = th_info->nmap;
    uint16_t port_index = nmap->port_dictionary[port];
    if (port_index == MAX_PORTS) return;
    if (th_info->host->port_states[th_info->current_scan][port_index] == PORT_UNDEFINED) {
        th_info->host->port_states[th_info->current_scan][port_index] = port_state;

        pthread_mutex_lock(&nmap->mutex_undefined_count);
        --th_info->host->undefined_count[th_info->current_scan];
        bool zero = th_info->host->undefined_count[th_info->current_scan] == 0;
        pthread_mutex_unlock(&nmap->mutex_undefined_count);
        if (nmap->is_sudo && zero) pcap_breakloop(th_info->globals.current_handle);
    }
}

void set_default_port_states(t_thread_info* th_info) {
    for (int i = 0; i < th_info->nmap->port_count; ++i) {
        if (th_info->host->port_states[th_info->current_scan][i] == PORT_UNDEFINED) {
            th_info->host->port_states[th_info->current_scan][i] = default_port_state[th_info->current_scan];
        }
    }
}
