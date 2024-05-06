from collections import defaultdict
from heapq import nlargest
from operator import itemgetter
import re

TOP_PORTS = 10  # TODO: 1024

tcp_probabilities = defaultdict(float)
udp_probabilities = defaultdict(float)
mixed_probabilities = defaultdict(float)

for line in open("scripts/etc_services").readlines():
    if fullmatch := re.fullmatch(r"[\w-]+\s+(\d+)/(tcp|udp)\s+(0.\d+).*", line.strip()):
        port, protocol, probability = fullmatch.groups()
        port = int(port)
        probability = float(probability)
        mixed_probabilities[port] += probability
        (tcp_probabilities if protocol == "tcp" else udp_probabilities)[port] += (
            probability
        )

for k, v in nlargest(TOP_PORTS, tcp_probabilities.items(), key=itemgetter(1)):
    print(k, v)
