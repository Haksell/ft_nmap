#include "ft_nmap.h"

// TODO: MESSAGE_HELP and MESSAGE_VERSION instead of functions that just call fprintf

static void print_help() {
    printf("ft_nmap <ip/hostname/file> [options]\n"
           "--help      Print this help screen\n"
           "--ports     Ports to scan (e.g. 1-10 or 1,2,3 or 1,5-15)\n"
           "--scans     ACK/FIN/NULL/SYN/UDP/XMAS\n"
           "--threads   Number of parallel threads to use (0-255)\n"
           "--version   Print version number\n");
}

static void print_version() { printf("ft_nmap version " VERSION "\n"); }

void handle_info_args(option_value new_opt, uint8_t nmap_opts) {
    if (new_opt == OPT_HELP && !(nmap_opts & new_opt)) print_help();
    if (new_opt == OPT_VERSION && !(nmap_opts & new_opt)) print_version();
}