#include "ft_nmap.h"

#define MESSAGE_VERSION "ft_nmap version " VERSION "\n"

void handle_info_args(option_value new_opt, uint32_t nmap_opts) {
    if (nmap_opts & new_opt) return;
    if (new_opt == OPT_VERSION) printf("ft_nmap version " VERSION "\n");
    else if (new_opt == OPT_HELP) {
        printf("ft_nmap <ip/hostname/file> [options]\n");
        printf("--help      Print this help screen\n");
        printf("--ports     Ports to scan (e.g. 1-10 or 1,2,3 or 1,5-15)\n");
        printf("--scans     ACK/CONN/FIN/NULL/SYN/UDP/WIN/XMAS\n");
        printf("--threads   Number of parallel threads to use (0-255)\n");
        printf("--version   Print version number\n");
    }
}
