#include "../ft_nmap.h"

void print_help() {
    fprintf(
        stdout, "ft_nmap [OPTIONS]\n"
                "--help Print this help screen\n"
                "--ports ports to scan (eg: 1-10 or 1,2,3 or 1,5-15)\n"
                "--ip ip addresses to scan in dot format\n"
                "--file File name containing IP addresses to scan,\n"
                "--speedup [250 max] number of parallel threads to use\n"
                "--scan SYN/NULL/FIN/XMAS/ACK/UDP\n"
    );
    exit(EXIT_SUCCESS);
}