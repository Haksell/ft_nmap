#include "ft_nmap.h"

#define MESSAGE_VERSION "ft_nmap version " VERSION "\n"

void handle_info_args(option_value new_opt, uint8_t nmap_opts) {
    if (new_opt == OPT_VERSION && !(nmap_opts & new_opt)) printf("ft_nmap version " VERSION "\n");
    else if (new_opt == OPT_HELP && !(nmap_opts & new_opt)) {
        printf("ft_nmap <ip/hostname/file> [options]\n");
        printf("--help      Print this help screen\n");
        printf("--ports     Ports to scan (e.g. 1-10 or 1,2,3 or 1,5-15)\n");
        printf("--scans     ACK/CONN/FIN/NULL/SYN/UDP/WIN/XMAS\n");
        printf("--threads   Number of parallel threads to use (0-255)\n");
        printf("--version   Print version number\n");
    }
}
