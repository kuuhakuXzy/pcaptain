
fast_scan — quick protocol inference from pcap files

Overview
--------
A tiny, fast C++ tool that walks packet headers and emits a simple protocol path (e.g. "eth:ip:tcp:https"). The scanner uses libpcap to read files and a small built-in port->application table for inference.

Prerequisites
-------------
- `g++` (or another C++17-capable compiler)
- `libpcap` development headers (install package `libpcap-dev` on Debian/Ubuntu)

Build
-----
From the `fast_scan` directory run:

```bash
g++ -O3 -std=c++17 fast_scan.cpp -lpcap -o fastscan
```

Run
---
Usage:

```bash
./fastscan path/to/file.pcap > output.txt
```

Each line of `output.txt` is a colon-separated protocol path detected in a packet (examples: `eth:ip:tcp:http`, `ipv6:udp:dns`).

Update inference (well-known ports)
----------------------------------
The inference table is defined in [well_know_port.h](well_know_port.h). To add or change entries:

1. Open `well_know_port.h` and edit the `init_port_table()` function.
2. Add a line using the `set()` helper, for example:

```cpp
set(12345, BIT_TCP | BIT_UDP, "myproto");
```

- `BIT_TCP`, `BIT_UDP`, `BIT_SCTP`, `BIT_DCCP` are defined at the top of `well_know_port.h`.
- The lookup uses the smaller of source/destination port as the key (see `lookup_port`).

After editing, rebuild with the same `g++` command above.

Files
-----
- Source: [fast_scan/fast_scan.cpp](fast_scan/fast_scan.cpp)
- Port table: [fast_scan/well_know_port.h](fast_scan/well_know_port.h)

Notes
-----
- Link with `-lpcap` is required.
- The tool reads offline pcap files via libpcap and prints inferred protocol paths to stdout; redirect as needed.
- For large captures, consider piping output to `sort | uniq -c` to summarise occurrences.

Tshark supported protocols list
file: [fast_scan/tshark_protocol_code.txt](fast_scan/tshark_protocol_code.txt)
```bash
tshark -G fields | awk -F'\t' '$1=="P"{print $2 "\t" $3}' > tshark_protocol_code.txt 
```

License
-------
No license specified — reuse at your discretion or add a LICENSE file.

