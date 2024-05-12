#include "ft_nmap.h"
#include <stdlib.h>

#define SNAP_LEN 1518 // maximum size of ethernet packet

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

void set_filter(t_thread_info* th_info, scan_type scan_type) {
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

static void panic_init_pcap(t_nmap* nmap, const char* format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    cleanup(nmap);
    exit(EXIT_FAILURE);
}

static pcap_t* set_handle(t_nmap* nmap, char* dev) {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* handle = pcap_open_live(dev, SNAP_LEN, 1, 1, errbuf);
    if (handle == NULL) panic_init_pcap(nmap, "Couldn't open device %s: %s\n", dev, errbuf);
    if (pcap_datalink(handle) != DLT_EN10MB) {
        pcap_close(handle);
        panic_init_pcap(nmap, "%s is not an Ethernet\n", dev);
    }
    return handle;
}

static void lookup_net(t_nmap* nmap, char* name, bpf_u_int32* device) {
    char errbuf[PCAP_ERRBUF_SIZE];
    if (pcap_lookupnet(name, device, &(bpf_u_int32){0}, errbuf) == PCAP_ERROR) {
        panic_init_pcap(nmap, "Couldn't get netmask for device %s: %s\n", name, errbuf);
    }
}

void init_pcap(t_nmap* nmap) {
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&nmap->devs, errbuf) == PCAP_ERROR) {
        panic_init_pcap(nmap, "nmap: couldn't find all devices", errbuf);
    }
    lookup_net(nmap, "lo", &nmap->device_lo);
    lookup_net(nmap, nmap->devs->name, &nmap->device_net);

    for (uint16_t i = 0; i < nmap->num_handles; ++i) {
        thread_globals[i].handle_lo = set_handle(nmap, "lo");
        thread_globals[i].handle_net = set_handle(nmap, nmap->devs->name);
        unset_filters(nmap, i);
    }
}
