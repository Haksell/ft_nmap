#include "ft_nmap.h"

static void get_service_name(uint16_t port, const char* proto, char buffer[MAX_SERVICE_LEN + 1]) {
    struct servent* service = getservbyport(htons(port), proto);
    char* service_name = service ? service->s_name : "unknown";
    strncpy(buffer, service_name, MAX_SERVICE_LEN);
    buffer[MAX_SERVICE_LEN] = '\0';
}

void get_service_names(t_nmap* nmap) {
    for (uint16_t port_index = 0; port_index < nmap->port_count; ++port_index) {
        uint16_t port = nmap->port_array[port_index];
        get_service_name(port, "tcp", nmap->tcp_services[port_index]);
        get_service_name(port, "udp", nmap->udp_services[port_index]);
    }
}
