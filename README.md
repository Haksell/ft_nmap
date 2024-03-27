# ft_nmap

## todo

### axbrisse

-   [ ] output ne pas afficher si plus de 25 closed, filtered, etc (is_responsive array)
-   [ ] clean `t_nmap`: `t_host`, remove fields that can be local variables...
-   [ ] better directory structure (based on ending/receiving threads?)
-   [ ] randomize ports
-   [ ] parsing tester

### lsimanic

-   [ ] better help menu
-   [ ] `--usage`
-   [ ] randomize source port

### whoever

-   [ ] forbid non-root user (except for info flags (and CONNECT scan?))
-   [ ] don't print report on Ctrl+C
-   [ ] fix `Host xxx is down` when scanning multiple hosts (et quand on Ctrl+C ca meurt)
-   [ ] consistent usage of `error`, `g_error`, `args_error`, `panic`, `exit` and `fprintf(stderr)`

## mandatory

-   [x] The executable must be named ft_nmap.
-   [ ] A help menu must be available. > Lorenzo faire un help de ouf
-   [x] You must only manage a simple IPv4 (address/hostname) as parameter for your scans.
-   [ ] You must manage FQDN however you don’t have to make the DNS resolution.
-   [ ] It must be possible to choose the number of threads (default:0 max:250) to make the scan faster
-   [ ] It must be possible to read a list of IPv4 addresses and hostname from a file (formatting is free).
-   [x] Your program must be able to run the following scan: SYN
-   [x] Your program must be able to run the following scan: NULL
-   [ ] Your program must be able to run the following scan: ACK > bug overflow
-   [x] Your program must be able to run the following scan: FIN
-   [x] Your program must be able to run the following scan: XMAS
-   [x] Your program must be able to run the following scan: UDP
-   [x] If the scan type is not specified then all scan types must be used.
-   [x] We must be able to run each type of scan individually, and several scans simultaneously.
-   [x] The ports to be scanned can be read as a range or individually.
-   [x] In the case no port is specified the scan must run with the range 1-1024.
-   [x] The number of ports scanned cannot exceed 1024.
-   [x] The resolution of service types will be requested (not the version but only the TYPE).
-   [x] The result of a scan should be as clean and clear as possible. The time frame should be easy to read.

## bonus

-   [ ] DNS/Version management.
-   [ ] OS detection.
-   [ ] Flag to go over the IDS/Firewall.
-   [ ] Being able to hide the source address. (IP spoofing? ez)
-   [ ] CIDR ranges [c-syn-scan-network](https://github.com/williamchanrico/c-syn-scan-network)
-   [ ] Additional flags...
-   [ ] Additional scans... (TCP Connect, TCP Window, TCP Maimon, SCTP INIT)
-   [ ] Different output formats (XML, grepable)
-   [ ] Flag for n most common ports instead of just 1-1024
-   [ ] `-iR`

## push check

-   [ ] `valgrind --leak-check=full --show-leak-kinds=all --track-fds=yes --track-origins=yes`
-   [ ] static all the functions
-   [ ] check forbidden functions
-   [ ] consistent typedef names (PascalCase or t_snake_case)
-   [ ] remove unused libraries

## tests

-   [ ] `./ft_nmap --help` lol
-   [ ] `./ft_nmap 8.8.8.8 --threads 70 --ports 70-90 --scans SYN`
-   [ ] `./ft_nmap 8.8.8.8 --threads 200 --ports 75-85`
-   [ ] faire un script qui fait 1000 portes x 6 scans sur nmap et compare avec le notre pour plusieurs hostnames

## resources

-   https://en.wikipedia.org/wiki/Transmission_Control_Protocol
-   https://en.wikipedia.org/wiki/User_Datagram_Protocol
-   https://nmap.org/book/toc.html
-   https://nmap.org/book/man.html
-   https://nmap.org/phrack54-09.txt
-   https://www.it-connect.fr/les-scans-de-port-via-tcp-syn-connect-et-fin/
-   https://www.it-connect.fr/les-scans-de-port-via-tcp-xmas-null-et-ack/
-   https://www.it-connect.fr/technique-de-scan-de-port-udp/
-   https://www.tcpdump.org/manpages/pcap.3pcap.html
-   https://www.tcpdump.org/pcap.html
-   http://yuba.stanford.edu/~casado/pcap/section1.html
-   https://www.devdungeon.com/content/using-libpcap-c
