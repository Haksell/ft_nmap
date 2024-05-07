from dataclasses import dataclass, fields
import os
import re
import requests
import sys

URL = "https://svn.nmap.org/nmap/nmap-service-probes"
FILENAME = "nmap-service-probes"
MAX_RANGES = 64
MAX_PAYLOAD_LENGTH = 1024
ESCAPES = {"\\": 92, "0": 0, "a": 7, "b": 8, "f": 12, "n": 10, "r": 13, "t": 9, "v": 11}


@dataclass
class Probe:
    rarity: int
    payload_start: int
    payload_end: int
    port_ranges_start: int
    port_ranges_end: int


def triplets(it):
    return zip(it, it[1:], it[2:])


def get_lines():
    if not os.path.exists(FILENAME):
        res = requests.get(URL)
        if res.status_code != 200:
            print("Failed with status code", res.status_code)
            sys.exit(1)
        open(FILENAME, "w").write(res.text)
    return open(FILENAME).read().strip().split("\n")


def parse_payload(s):
    payload = []
    i = 0
    while i < len(s):
        if s[i] == "\\":
            assert i + 1 < len(s)
            nxt = s[i + 1]
            if nxt == "x":
                assert i + 3 < len(s)
                payload.append(int(s[i + 2 : i + 4], 16))
                i += 4
            else:
                assert nxt in ESCAPES, nxt
                payload.append(ESCAPES[nxt])
                i += 2
        else:
            payload.append(ord(s[i]))
            i += 1
    assert len(payload) <= MAX_PAYLOAD_LENGTH
    return payload


def parse_ranges(ports_line):
    str_ranges = ports_line.split()[1].split(",")
    assert len(str_ranges) <= MAX_RANGES, len(str_ranges)
    port_ranges = []
    for port in str_ranges:
        if "-" in port:
            start, end = map(int, port.split("-"))
            assert start <= end
        else:
            start = end = int(port)
        port_ranges.append((start, end))
    return port_ranges


def parse_probes():
    concatenated_payloads = []
    concatenated_port_ranges = []
    probes = []
    for line1, line2, line3 in triplets(get_lines()):
        if not line1.startswith("Probe UDP"):
            continue
        fullmatch = re.fullmatch(
            r"Probe UDP [\w-]+ q\|(.*)\|(?: (no-payload|source=500))?", line1
        )
        assert fullmatch
        if fullmatch.group(2) == "no-payload":
            continue
        ports_line, rarity_line = sorted([line2, line3])
        assert re.fullmatch(r"ports (\d+(-\d+)?)(,(\d+(-\d+)?))*", ports_line)
        assert re.fullmatch(r"rarity [1-9]", rarity_line)
        rarity = int(rarity_line.split()[1])
        payload_start = len(concatenated_payloads)
        port_ranges_start = len(concatenated_port_ranges)
        if fullmatch.group(2) != "no-payload":
            concatenated_payloads.extend(parse_payload(fullmatch.group(1)))
        concatenated_port_ranges.extend(parse_ranges(ports_line))
        probes.append(
            Probe(
                rarity,
                payload_start,
                len(concatenated_payloads),
                port_ranges_start,
                len(concatenated_port_ranges),
            )
        )
    return concatenated_payloads, concatenated_port_ranges, probes


TEMPLATE = """
#pragma once

#include "ft_nmap.h"

#define MAX_PAYLOAD_SIZE 512

typedef struct {{
    size_t rarity;
    size_t payload_start;
    size_t payload_end;
    size_t port_ranges_start;
    size_t port_ranges_end;
}} t_probe;

#define SENTINEL_RARITY 10
#define SENTINEL_PROBE ((t_probe){{SENTINEL_RARITY, 0, 0, 0, 0}})

static const uint8_t concatenated_payloads[] = {{
    {}
}};

static const uint16_t concatenated_port_ranges[] = {{
    {}
}};

static const t_probe udp_probes[] = {{
    {},
    SENTINEL_PROBE,
}};
"""


def write_probes(concatenated_payloads, concatenated_port_ranges, probes):
    open("include/udp_probes.h", "w").write(
        TEMPLATE.format(
            ", ".join(map(str, concatenated_payloads)),
            ", ".join(f"{start}, {end}" for start, end in concatenated_port_ranges),
            ", ".join(
                f"{{{', '.join(str(getattr(p, f.name)) for f in fields(p))}}}"
                for p in probes
            ),
        )
    )


write_probes(*parse_probes())
