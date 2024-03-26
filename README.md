# ft_nmap

## todo

-   [ ] 4 other types of scans (except UDP)
-   [ ] UDP scan
-   [ ] align output
-   [ ] parsing tester
-   [ ] file shoudln't be a named argument (`ft_nmap <ip/hostname/file> [options]`)
-   [ ] `--usage`
-   [ ] forbid non-root user (except for info flags (and CONNECT scan?))
-   [ ] don't print report on Ctrl+C

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
-   [x] The ports to be scanned can be read as a range or individually.
-   [x] In the case no port is specified the scan must run with the range 1-1024.
-   [x] The number of ports scanned cannot exceed 1024.
-   [x] The resolution of service types will be requested (not the version but only the TYPE).
-   [ ] The result of a scan should be as clean and clear as possible. The time frame should be easy to read.

## bonus

-   [ ] DNS/Version management.
-   [ ] OS detection.
-   [ ] Flag to go over the IDS/Firewall.
-   [ ] Being able to hide the source address. (IP spoofing? ez)
-   [ ] CIDR ranges [c-syn-scan-network](https://github.com/williamchanrico/c-syn-scan-network)
-   [ ] Additional flags...
-   [ ] Additional scans... (TCP Connect, TCP Window, TCP Maimon, SCTP INIT)
-   [ ] Different output formats (XML, grepable)

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

```
pro: randomize source port for no detection -> sequentielle et on est detecté
randomize type of scan -> de facon random on change de type de scan (multi-threading?)
pseudocode qui est illogique
    port = rand() % remaning_ports
    type = rand() % remaning_types
    if (!get_port(namp.ports, port, SCAN_FIN) set_port(nmap.ports, port, SCAN_FIN) -> on a
    scanné ce port avec FIN, donc on va pas le refaire if (setport a set tout a 0)
    remaning_ports-- (i know ca marche pas comme ça, mais le concept est de raccourcir la
    liste de ports a scanner a chaque fois qu'on en a fully scanné un) if (type.count ==
    port_count) remaning_types-- (meme concept que pour les ports, mais pour les types de
    scan) if (remaning_ports == 0) break; (si on a scanné tous les ports, on sort de la
    boucle)

    print results (que il faudra donc stocker dans une structure. a diffrence de ping, nmap
    a besoin de stocker les resultats pour les afficher a la fin). justement parce-que il
    randomize les ports et les types de scan, il pourra pas afficher les resultats dans
    l'ordre.

// TODO creer un header TCP (regarder ping.c pour exemple de header IP
// TODO creer un pseudo header
// TODO calculer le checksum
// TODO envoyer le paquet
```

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
