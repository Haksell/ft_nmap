RESET = "\x1b[0m"


def read_file(filename):
    lines = open(filename).read().strip().splitlines()[2:-2]
    joined = "\n".join(lines)
    groups = sorted(s.strip().split("\n") for s in joined.split(RESET))
    reports = dict()
    for g in groups:
        host = g[0].split()[4]
        if host in reports:
            print(host)
            continue
        reports[host] = g[1:]
    return reports


reports24 = read_file("24NEWNEW")
reports250 = read_file("250RELOADED")

print("hosts in 24, not 250", set(reports24) - set(reports250))
print("hosts in 250, not 24", set(reports250) - set(reports24))
shared_keys = set(reports24) & set(reports250)
count = 0
for k in shared_keys:
    v24 = reports24[k]
    v250 = reports250[k]
    if v24[0].startswith("rDNS"):
        v24.pop(0)
    if v250[0].startswith("rDNS"):
        v250.pop(0)
    if v24 != v250:
        print(k)
        print()
        print("\n".join(v24))
        print()
        print("\n".join(v250))
        print("\n=====================================\n")
        count += 1
print(count, "differences")
