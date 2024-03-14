# ft_nmap

## mandatory

-   [x] The executable must be named ft_nmap.
-   [ ] A help menu must be available.
-   [ ] You must only manage a simple IPv4 (address/hostname) as parameter for your scans.
-   [ ] You must manage FQDN however you don’t have to make the DNS resolution.
-   [ ] It must be possible to choose the number of threads (default:0 max:250) to make the scan faster
-   [ ] It must be possible to read a list of IPv4 addresses and hostname from a file (formatting is free).
-   [ ] Your program must be able to run the following scans: SYN, NULL, ACK, FIN, XMAS, UDP
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
-   [ ] Being able to hide the source address.
-   [ ] Additional flags...

## push check

-   [ ] `valgrind --leak-check=full --show-leak-kinds=all --track-fds=yes --track-origins=yes`
-   [ ] static all the functions
-   [ ] check forbidden functions

## tests

-   [ ] `./ft_nmap --help`
-   [ ] `./ft_nmap --ip 8.8.8.8 --speedup 70 --port 70-90 --scan SYN`
-   [ ] `./ft_nmap --ip x.x.x.x --speedup 200 --port 75-85`

## misc

-   use `-lpcap`
-   use `-lpthread`
-   use `clock_gettime`

## resources

-   https://en.wikipedia.org/wiki/Nmap
-   https://linux.die.net/man/1/nmap
