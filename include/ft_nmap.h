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

#define TCP_HEADER_SIZE sizeof(struct tcphdr)
#define IP_HEADER_SIZE sizeof(struct iphdr)
#define PSEUDO_HEADER_SIZE sizeof(struct pseudohdr)
#define NMAP_PACKET_SIZE (IP_HEADER_SIZE + TCP_HEADER_SIZE)

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

typedef struct {
    int fd;
    uint8_t* packet;
    char hostname[HOST_NAME_MAX + 1];
    char hostip[INET_ADDRSTRLEN + 1];
    struct sockaddr_in hostaddr;

    uint32_t opt;
    FILE* file; // TODO: close
    uint64_t ports[1024];
    uint8_t scans; // TODO: maybe 16
    uint8_t threads;

    struct timeval start_time;
} t_nmap;

static const option valid_opt[] = {
    {OPT_FILE,    'f', "file",    true },
    {OPT_HELP,    'h', "help",    false},
    {OPT_PORTS,   'p', "ports",   true },
    {OPT_SCAN,    's', "scans",   true },
    {OPT_THREADS, 't', "threads", true },
    {OPT_VERSION, 'v', "version", false},
    {OPT_VERBOSE, 'V', "verbose", false},
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

// debug.c (TODO: remove)
void print_ports(uint64_t* ports);
void print_scans(uint8_t scans);

// info.c
void handle_info_args(option_value new_opt, uint8_t nmap_opts);

// main.c
void verify_arguments(int argc, char* argv[], t_nmap* nmap);

// packet.c
void fill_packet(uint8_t* packet, struct sockaddr_in target, uint16_t port);

// pcap.c
void* capture_packets(__attribute__((unused)) void* arg);
void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet);
void init_pcap(capture_args_t* capture_args);

// ports.c
bool get_port(uint64_t* ports, uint16_t port);
void set_port(uint64_t* ports, uint16_t port);

// random.c
uint32_t random_u32_range(uint32_t a, uint32_t b);

// utils.c
void error(char* message);
void g_error(char* message, int status);
void hostname_to_ip(t_nmap* nmap);
bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen);
in_addr_t get_source_address();
void panic(const char* format, ...);
