# ft_nmap

## fix today

- [ ] fix ping
- [ ] fix up count
- [ ] `CONN` before `SYN`, `WIN` after `ACK`
- [ ] find `hostip` of every host during parsing and put it in `t_host`
- [ ] `--retransmissions` flag (time proportional to undefined count and latency)
- [ ] `CONN`: no sudo, timeout, more even segmentations (and bigger than 512), own separate thread
- [ ] `UDP`: multiple sockets like `CONN`, better handling of multiple payloads
- [ ] no more usleep

## mandatory

- [x] The executable must be named ft_nmap.
- [ ] A help menu must be available.
- [x] You must only manage a simple IPv4 (address/hostname) as parameter for your scans.
- [x] You must manage FQDN however you don’t have to make the DNS resolution.
- [x] It must be possible to choose the number of threads (default:0 max:250) to make the scan faster
- [x] It must be possible to read a list of IPv4 addresses and hostname from a file. (parsing good, execution bad)
- [x] Your program must be able to run the following scan: SYN
- [x] Your program must be able to run the following scan: NULL
- [x] Your program must be able to run the following scan: ACK
- [x] Your program must be able to run the following scan: FIN
- [x] Your program must be able to run the following scan: XMAS
- [x] Your program must be able to run the following scan: UDP
- [x] If the scan type is not specified then all scan types must be used.
- [x] We must be able to run each type of scan individually, and several scans simultaneously.
- [x] The ports to be scanned can be read as a range or individually.
- [x] In the case no port is specified the scan must run with the range 1-1024.
- [x] The number of ports scanned cannot exceed 1024.
- [x] The resolution of service types will be requested (not the version but only the TYPE).
- [x] The result of a scan should be as clean and clear as possible. The time frame should be easy to read.

## bonus

### ez

- [x] Reverse DNS
- [x] CIDR ranges
- [x] `--no-randomize`
- [x] `--no-ping`
- [x] `--top-ports`
- [x] `-sW` SCAN_WIN
- [ ] `-sC` SCAN_CONN
- [ ] UDP version detection

### wtf

- [ ] TCP version detection (???)
- [ ] `--spoof-address` (hide source address)
- [ ] `--decoy`
- [ ] `--fragment-packets`
- [ ] other flags to go over the IDS/Firewall (FIREWALL/IDS EVASION AND SPOOFING section)

## push check

- [ ] `valgrind --leak-check=full --show-leak-kinds=all --track-fds=yes --track-origins=yes`
- [ ] static all the functions
- [ ] check forbidden functions
- [ ] consistent typedef names (PascalCase or t_snake_case)
- [ ] remove unused libraries
- [ ] remove `garbage` and `output` folders (and maybe `hosts`?)
- [ ] `help` corresponds to actual flags
- [ ] remove fsanitize from Makefile
