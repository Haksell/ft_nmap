#include "ft_nmap.h"

extern t_thread_globals thread_globals[MAX_HOSTNAMES];

static void set_device_filter(pcap_t* handle, bpf_u_int32 device, char* filter_exp) {
    struct bpf_program fp;

    if (pcap_compile(handle, &fp, filter_exp, 0, device) == PCAP_ERROR)
        panic("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
    if (pcap_setfilter(handle, &fp) == PCAP_ERROR)
        panic("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
    pcap_freecode(&fp);
}

void unset_filters(t_nmap* nmap, uint16_t t_index) {
    static char filter_none[] = "tcp and not ip";
    pthread_mutex_lock(&nmap->mutex_pcap_filter);
    set_device_filter(thread_globals[t_index].handle_lo, nmap->device_lo, filter_none);
    set_device_filter(thread_globals[t_index].handle_net, nmap->device_net, filter_none);
    pthread_mutex_unlock(&nmap->mutex_pcap_filter);
}

void set_filter(t_thread_info* th_info, t_scan_type scan_type) {
    char filter_exp[256] = {0};
    char* hostip = th_info->host->hostip;

    if (scan_type == SCAN_MAX) {
        sprintf(filter_exp, "icmp and src %s", hostip);
    } else if (scan_type == SCAN_UDP) {
        sprintf(filter_exp, "(src host %s and udp) or (icmp and src %s)", hostip, hostip);
    } else {
        sprintf(
            filter_exp,
            "(src host %s and tcp and dst port %d) or (icmp and src %s)",
            hostip,
            th_info->port_source,
            hostip
        );
    }

    bpf_u_int32 current_device = th_info->globals.current_handle == th_info->globals.handle_lo
                                     ? th_info->nmap->device_lo
                                     : th_info->nmap->device_net;

    pthread_mutex_lock(&th_info->nmap->mutex_pcap_filter);
    set_device_filter(th_info->globals.current_handle, current_device, filter_exp);
    pthread_mutex_unlock(&th_info->nmap->mutex_pcap_filter);
}
