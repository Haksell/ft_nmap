import sys

RESET = "\x1b[0m"


def read_reports(filename):
    def duplicate(host):
        if host in downs or host in reports:
            print(f"Duplicate {host} in {filename}")
            return True
        else:
            return False

    *lines, _, up_count = open(filename).read().strip().splitlines()[2:]
    up_count = int(up_count.split("(")[1].split(" ")[0])
    joined = "\n".join(lines)
    groups = sorted(s.strip().split("\n") for s in joined.split(RESET))
    downs = set()
    reports = dict()
    for g in groups:
        if "is down" in g[0]:
            host = g[0].split()[1]
            if not duplicate(host):
                downs.add(host)
        else:
            host = g[0].split()[4]
            if not duplicate(host):
                reports[host] = g[1:]
    return downs, reports, up_count


def get_report(reports, key):
    report = reports[key]
    if report[0].startswith("Host"):
        report.pop(0)
    if report[0].startswith("rDNS"):
        report.pop(0)
    return report


def main():
    downs1, reports1, up_count1 = read_reports(sys.argv[1])
    downs2, reports2, up_count2 = read_reports(sys.argv[2])

    if up_count1 != up_count2:
        print(
            f"{up_count1} hosts up in {sys.argv[1]}, {up_count2} hosts up in {sys.argv[2]}"
        )
    if up1 := set(reports1) - set(reports2):
        print(f"Hosts up in {sys.argv[1]}, not {sys.argv[2]}:", *up1)
    if up2 := set(reports2) - set(reports1):
        print(f"Hosts up in {sys.argv[2]}, not {sys.argv[1]}:", *up2)
    if down1 := set(downs1) - set(downs2):
        print(f"Hosts down in {sys.argv[1]}, not {sys.argv[2]}:", *down1)
    if down2 := set(downs2) - set(downs1):
        print(f"Hosts down in {sys.argv[2]}, not {sys.argv[1]}:", *down2)
    count = 0
    for k in set(reports1) & set(reports2):
        report1 = get_report(reports1, k)
        report2 = get_report(reports2, k)
        if report1 != report2:
            print("=============================================================")
            print(k)
            print(f"=== {sys.argv[1]} ===")
            print("\n".join(report1))
            print(f"=== {sys.argv[2]} ===")
            print("\n".join(report2))
            print("=============================================================")
            count += 1
    print(f"{count} difference{'s' if count >= 2 else ''} found")


if __name__ == "__main__":
    main()
