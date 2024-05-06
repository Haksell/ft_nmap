from collections import defaultdict
from heapq import nlargest
import re

TOP_PORTS = 1024
PROTOCOLS = ["mixed", "tcp", "udp"]

probabilities = {p: defaultdict(float) for p in PROTOCOLS}
for line in open("/etc/services").readlines():
    if fullmatch := re.fullmatch(r"[\w-]+\s+(\d+)/(tcp|udp)\s+(0.\d+).*", line.strip()):
        port, protocol, probability = fullmatch.groups()
        probabilities[protocol][int(port)] += float(probability)

for port, proba in probabilities["udp"].items():
    probabilities["mixed"][port] += proba
factor = sum(probabilities["udp"].values()) / sum(probabilities["tcp"].values())
for port, proba in probabilities["tcp"].items():
    probabilities["mixed"][port] += proba * factor

output = ["#pragma once", "", '#include "ft_nmap.h"', ""]
for protocol in PROTOCOLS:
    output.append(f"static const uint16_t top_ports_{protocol}[MAX_PORTS] = {{")
    pbp = probabilities[protocol]
    for port in nlargest(TOP_PORTS, pbp, key=pbp.get):
        output.append(f"    {port},")
    output.append("};")
    output.append("")
open("include/top_ports.h", "w").write("\n".join(output))
