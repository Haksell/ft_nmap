from collections import defaultdict
import os
import re
import requests
import sys

FILENAME = "nmap-service-probes"
if not os.path.exists(FILENAME):
    res = requests.get("https://svn.nmap.org/nmap/nmap-service-probes")
    if res.status_code != 200:
        print("Failed with status code", res.status_code)
        sys.exit(1)
    open(FILENAME, "w").write(res.text)


def triplets(it):
    return zip(it, it[1:], it[2:])


counts = defaultdict(int)
lines = open(FILENAME).read().strip().split("\n")
for probe_udp, line2, line3 in triplets(lines):
    if probe_udp.startswith("Probe UDP"):
        ports, rarity = sorted([line2, line3])
        assert re.fullmatch(r"ports (\d+(-\d+)?)(,(\d+(-\d+)?))*", ports)
        assert re.fullmatch(r"rarity \d+", rarity)
        print(probe_udp)
        print(ports)
        print()
