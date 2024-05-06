from heapq import nlargest
import re

TOP_PORTS = 1024
PROTOCOLS = ["mixed", "tcp", "udp"]

probabilities = {p: dict() for p in PROTOCOLS}

for line in open("scripts/etc_services").readlines():
    if fullmatch := re.fullmatch(r"[\w-]+\s+(\d+)/(tcp|udp)\s+(0.\d+).*", line.strip()):
        port, protocol, probability = fullmatch.groups()
        port = int(port)
        probability = float(probability)
        probabilities[protocol][port] = probability

factor = sum(probabilities["udp"].values()) / sum(probabilities["tcp"].values())
for port in set(probabilities["tcp"].keys()) | set(probabilities["udp"].keys()):
    probabilities["mixed"][port] = probabilities["tcp"].get(
        port, 0
    ) * factor + probabilities["udp"].get(port, 0)


def format_array(output, protocol):
    output.append(f"static const uint16_t top_ports_{protocol}[MAX_PORTS] = {{")
    pbp = probabilities[protocol]
    for port in nlargest(TOP_PORTS, pbp, key=pbp.get):
        output.append(f"    {port},")
    output.append("};")
    output.append("")


output = ["#pragma once", "", '#include "ft_nmap.h"', ""]
for protocol in PROTOCOLS:
    format_array(output, protocol)
open("include/top_ports.h", "w").write("\n".join(output))
