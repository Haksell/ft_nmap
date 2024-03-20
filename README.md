# ft_nmap

## todo

-   [ ] install and learn libpcap
-   [ ] parsing tester
-   [ ] basic SYN scan [c-syn-scan-network](https://github.com/williamchanrico/c-syn-scan-network) [port-scanner (uses libpcap)](https://github.com/kacpal/port-scanner)
-   [ ] file shoudln't be a named argument (`ft_nmap <ip/hostname/file> [options]`)
-   [ ] `--usage`
-   [ ] forbid non-root user (except for info flags (and CONNECT scan?))

## mandatory

-   [x] The executable must be named ft_nmap.
-   [ ] A help menu must be available.
-   [ ] You must only manage a simple IPv4 (address/hostname) as parameter for your scans.
-   [ ] You must manage FQDN however you don’t have to make the DNS resolution.
-   [ ] It must be possible to choose the number of threads (default:0 max:250) to make the scan faster
-   [ ] It must be possible to read a list of IPv4 addresses and hostname from a file (formatting is free).
-   [ ] Your program must be able to run the following scan: SYN
-   [ ] Your program must be able to run the following scan: NULL
-   [ ] Your program must be able to run the following scan: ACK
-   [ ] Your program must be able to run the following scan: FIN
-   [ ] Your program must be able to run the following scan: XMAS
-   [ ] Your program must be able to run the following scan: UDP
-   [ ] If the scan type is not specified then all scan types must be used.
-   [ ] We must be able to run each type of scan individually, and several scans simultaneously.
-   [ ] The ports to be scanned can be read as a range or individually.
-   [ ] In the case no port is specified the scan must run with the range 1-1024.
-   [ ] The number of ports scanned cannot exceed 1024.
-   [ ] The resolution of service types will be requested (not the version but only the TYPE).
-   [ ] The result of a scan should be as clean and clear as possible. The time frame should be easy to read.

## bonus

-   [ ] DNS/Version management.
-   [ ] OS detection.
-   [ ] Flag to go over the IDS/Firewall.
-   [ ] Being able to hide the source address. (IP spoofing? ez)
-   [ ] CIDR ranges [c-syn-scan-network](https://github.com/williamchanrico/c-syn-scan-network)
-   [ ] Additional flags...
-   [ ] Additional scans... (TCO Connect, TCP Window, TCP Maimon, SCTP INIT)

## push check

-   [ ] `valgrind --leak-check=full --show-leak-kinds=all --track-fds=yes --track-origins=yes`
-   [ ] static all the functions
-   [ ] check forbidden functions

## tests

-   [ ] `./ft_nmap --help`
-   [ ] `./ft_nmap 8.8.8.8 --threads 70 --ports 70-90 --scans SYN`
-   [ ] `./ft_nmap 8.8.8.8 --threads 200 --ports 75-85`

## misc

-   use `-lpcap`
-   use `-lpthread`
-   use `clock_gettime` or just `clock`

## resources

-   https://en.wikipedia.org/wiki/Transmission_Control_Protocol
-   https://en.wikipedia.org/wiki/User_Datagram_Protocol
-   https://nmap.org/book/toc.html
-   https://nmap.org/book/man.html
-   https://www.it-connect.fr/les-scans-de-port-via-tcp-syn-connect-et-fin/
-   https://www.it-connect.fr/les-scans-de-port-via-tcp-xmas-null-et-ack/
-   https://www.it-connect.fr/technique-de-scan-de-port-udp/
-   https://www.tcpdump.org/manpages/pcap.3pcap.html
-   https://www.tcpdump.org/pcap.html
-   http://yuba.stanford.edu/~casado/pcap/section1.html
-   https://www.devdungeon.com/content/using-libpcap-c
