#pragma once

// TODO: bring back to root if it is only header file?

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "ft_pcap.h"

#define EXIT_ARGS 0xff
#define VERSION "0.4.2"

#define MAX_PORTS 1024
#define MAX_HOSTNAMES 256

#define TCP_HEADER_SIZE sizeof(struct tcphdr)
#define IP_HEADER_SIZE sizeof(struct iphdr)
#define PSEUDO_HEADER_SIZE sizeof(struct pseudohdr)
#define NMAP_PACKET_SIZE (IP_HEADER_SIZE + TCP_HEADER_SIZE)

typedef enum {
    PORT_UNDEFINED,
    PORT_OPEN,
    PORT_CLOSED,
    PORT_FILTERED,
    // TODO: PORT_UNFILTERED...,
} __attribute__((packed)) port_state;

typedef enum {
    OPT_FILE = 1 << 0,
    OPT_HELP = 1 << 1,
    OPT_PORTS = 1 << 2,
    OPT_SCAN = 1 << 3,
    OPT_THREADS = 1 << 4,
    OPT_VERSION = 1 << 5,
    OPT_VERBOSE = 1 << 6,
} option_value;

typedef struct {
    option_value opt;
    char short_opt;
    char* long_opt;
    bool has_arg;
} option;

typedef enum {
    SCAN_ACK = 1 << 0,
    SCAN_FIN = 1 << 1,
    SCAN_NULL = 1 << 2,
    SCAN_SYN = 1 << 3,
    SCAN_UDP = 1 << 4,
    SCAN_XMAS = 1 << 5,
} scan_type;

typedef struct {
    scan_type type;
    char name[5];
} scan;

// TODO: host struct with name, port_states, undefined_count...

typedef struct {
    int fd;
    uint8_t* packet;
    int hostname_count;
    char hostnames[MAX_HOSTNAMES][HOST_NAME_MAX + 1];
    char hostip[INET_ADDRSTRLEN + 1]; // one for each hostname
    int hostname_index;
    struct sockaddr_in hostaddr;

    uint32_t opt;
    FILE* file; // TODO: close
    uint16_t port_count;
    uint64_t port_set[1024];
    uint16_t port_array[MAX_PORTS];
    uint16_t port_dictionary[1 << 16];
    port_state port_states[MAX_HOSTNAMES][MAX_PORTS];
    uint16_t undefined_count[MAX_HOSTNAMES];
    uint8_t scans; // TODO: maybe uint16_t
    uint8_t current_scan;
    uint8_t threads;

    struct timeval start_time;
    struct timeval end_time;

    uint16_t port_source;

    pcap_if_t* devs;
    bpf_u_int32 net_device;
} t_nmap;

static const option valid_opt[] = {
    {OPT_FILE,    'f', "file",    true },
    {OPT_HELP,    'h', "help",    false},
    {OPT_PORTS,   'p', "ports",   true },
    {OPT_SCAN,    's', "scans",   true },
    {OPT_THREADS, 't', "threads", true },
    {OPT_VERBOSE, 'v', "verbose", false},
    {OPT_VERSION, 'V', "version", false},
    {0,           0,   NULL,      false}
};

static const scan valid_scans[] = {
    {SCAN_ACK,  "ACK" },
    {SCAN_FIN,  "FIN" },
    {SCAN_NULL, "NULL"},
    {SCAN_SYN,  "SYN" },
    {SCAN_UDP,  "UDP" },
    {SCAN_XMAS, "XMAS"},
    {0,         ""    },
};

static const char port_state_str[][10] = {"undefined", "open", "closed", "filtered"};

// capture_packets.c
void* capture_packets(__attribute__((unused)) void* arg);

// info.c
void handle_info_args(option_value new_opt, uint8_t nmap_opts);

// init_pcap.c
void set_filter(t_nmap* nmap);
void init_pcap(t_nmap* nmap);

// main.c
void verify_arguments(int argc, char* argv[], t_nmap* nmap);

// ports.c
bool get_port(uint64_t* ports, uint16_t port);
void set_port(t_nmap* nmap, uint16_t port);

// random.c
uint32_t random_u32_range(uint32_t a, uint32_t b);

// send_packets.c
void* send_packets(void* arg);

// signals.c
void handle_sigint(int sig);
void set_signals();

// utils.c
void error(char* message);
void g_error(char* message, int status);
void hostname_to_ip(t_nmap* nmap);
bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen);
in_addr_t get_source_address();
void panic(const char* format, ...);
void get_start_time(t_nmap* nmap);
void print_stats(t_nmap* nmap);
void cleanup(t_nmap* nmap);

// verbose.c
void print_hostnames(t_nmap* nmap);
void print_ports(t_nmap* nmap);
void print_scans(uint8_t scans);
