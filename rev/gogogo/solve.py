#!/usr/bin/env python3
import sys

path = 'gogogo'
data = open(path, 'rb').read()

best_start = best_run = 0
i, n = 0, len(data)

# Cari run terpanjang: [printable][\x00][\x00] berulang
while i < n - 24:  # 8*3 minimal
    s, run = i, 0
    while i + 2 < n and 32 <= data[i] <= 126 and data[i+1] == 0 and data[i+2] == 0:
        run += 1
        i += 3
    if run > best_run:
        best_run, best_start = run, s
    i = s + 1 if run == 0 else i

if best_run == 0:
    sys.exit("pattern not found")

core = data[best_start:best_start + 3*best_run:3].decode('ascii', 'ignore')
tail = data[best_start + 3*best_run: best_start + 3*best_run + 1]
if tail == b'}' and not core.endswith('}'):
    core += '}'

print(core)