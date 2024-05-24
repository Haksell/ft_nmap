import os
import re

NM_FILENAME = ".nm_output"
ALLOWED_FILENAME = "scripts/allowed.txt"

os.system(f"nm -u ./ft_nmap > {NM_FILENAME}")
nm_lines = re.findall(r"(?<=U )[a-z]\w+", open(NM_FILENAME).read())
allowed_lines = re.findall(r"\w+", open(ALLOWED_FILENAME).read())
print(*sorted(set(nm_lines) - set(allowed_lines)), sep="\n")
