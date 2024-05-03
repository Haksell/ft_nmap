# ft_nmap

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
- [ ] CIDR ranges [c-syn-scan-network](https://github.com/williamchanrico/c-syn-scan-network)
- [x] `--no-randomize`
- [x] `--no-ping`
- [ ] `--top-ports` -> Axel: python script to find the top ports with the % file. On avait déjà fait I think
- [x] `-sT` SCAN_CONNECT
- [ ] no sudo for SCAN_CONNECT
- [ ] no pcap for SCAN_CONNECT, a reflechir ensemble
- [ ] Axel: si tu veux `-sT` faudra changer un peu le parsing. Sinon on garde `-sC` comme maintenant.
- [x] `-sW` SCAN_WINDOW
- [x] UDP payload

### wtf

- [ ] `--version-detection` Version detection UDP (Lorenzo)
- [ ] `--version-detection` Version detection TCP (???)
- [ ] `-O` `--os` OS detection
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
- [ ] remove `garbage` folder (and maybe `hosts`?)
- [ ] `help` corresponds to actual flags
