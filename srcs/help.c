#include "ft_nmap.h"

void print_help() {
    fprintf(
        stdout, "ft_nmap <ip/hostname/file> [OPTIONS]\n"
                "--help Print this help screen\n"
                "--threads [250 max] number of parallel threads to use\n"
                "--ports ports to scan (e.g. 1-10 or 1,2,3 or 1,5-15)\n"
                "--scans SYN/NULL/FIN/XMAS/ACK/UDP\n"
    );
    exit(EXIT_SUCCESS);
}