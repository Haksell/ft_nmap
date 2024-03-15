#pragma once

// TODO: bring back to root if it is only header file?

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <signal.h>
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

#define EXIT_ARGS 0xff
#define VERSION "0.1"

#define MAX_PORTS 1024

typedef enum {
    OPT_FILE = 1 << 0,
    OPT_HELP = 1 << 1,
    OPT_PORTS = 1 << 2,
    OPT_SCAN = 1 << 3,
    OPT_THREADS = 1 << 4,
    OPT_VERSION = 1 << 5,
} option_value;

typedef struct {
    option_value opt;
    char short_opt;
    char* long_opt;
    bool has_arg;
} option;

typedef enum {
    SCAN_SYN = 1 << 0,
    SCAN_NULL = 1 << 1,
    SCAN_ACK = 1 << 2,
    SCAN_FIN = 1 << 3,
    SCAN_XMAS = 1 << 4,
    SCAN_UDP = 1 << 5,
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
} nmap;

static const option valid_opt[] = {
    {OPT_FILE,    'f', "file",    true },
    {OPT_HELP,    'h', "help",    false},
    {OPT_PORTS,   'p', "ports",   true },
    {OPT_SCAN,    's', "scans",   true },
    {OPT_THREADS, 't', "threads", true },
    {OPT_VERSION, 'V', "version", false},
    {0,           0,   NULL,      false}
};

static const scan valid_scans[] = {
    {SCAN_SYN,  "SYN" },
    {SCAN_NULL, "NULL"},
    {SCAN_ACK,  "ACK" },
    {SCAN_FIN,  "FIN" },
    {SCAN_XMAS, "XMAS"},
    {SCAN_UDP,  "UDP" },
    {0,         ""    },
};

// debug.c (TODO: remove)
void print_ports(uint64_t* ports);
void print_scans(uint8_t scans);

// help.c
void print_help();

// main.c
void verify_arguments(int argc, char* argv[], nmap* nmap);

// nmap_utils.c
void error(char* message);
void g_error(int status);
void hostname_to_ip(nmap* nmap);
bool ip_to_hostname(struct in_addr ip_address, char* host, size_t hostlen);

// nmap.c
void create_socket(nmap* nmap);

// ports.c
bool get_port(uint64_t* ports, uint16_t port);
void set_port(uint64_t* ports, uint16_t port);