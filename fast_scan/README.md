
fast_scan — quick protocol inference from pcap files

Overview
--------
A small, fast C++ tool that walks packet headers and emits a simple protocol path (for example: "eth:ip:tcp:https"). The scanner reads pcap files with libpcap and uses a lightweight port-to-application table for basic inference.

Prerequisites
-------------
- A C++17-capable compiler such as `g++` or `clang`.
- libpcap development headers (Debian/Ubuntu: `libpcap-dev`, macOS: via Homebrew `brew install libpcap`).
- CMake 3.12 or higher (optional, for cross-platform builds).

Build
-----

### Option 1: CMake (recommended for cross-platform)

From the `fast_scan` directory run:

```bash
mkdir build
cd build
cmake ..
make
```

The executable `fastscan` will be in the `build` directory. To install system-wide:

```bash
sudo make install
```

### Option 2: Direct compilation

From the `fast_scan` directory run:

```bash
g++ -O3 -std=c++17 \
    -Ilib \
    fast_scan.cpp src/scanner.cpp src/inference.cpp \
    -lpcap \
    -o fastscan
```

If your system installs headers in non-standard locations, add appropriate `-I` or linker flags.

Run
---
Usage:

```bash
./fastscan path/to/file.pcap > output.txt
```

Each line of `output.txt` is a colon-separated protocol path detected in a packet (examples: `eth:ip:tcp:http`, `ipv6:udp:dns`). For summaries, run `sort | uniq -c` on the output.

Inference (well-known ports)
----------------------------
Port-based inference is implemented in the project's source (see `src/inference.cpp`). To change or extend the port mappings, edit the port table in the source and rebuild.

Files
-----
- Source: [fast_scan/fast_scan.cpp](fast_scan/fast_scan.cpp)
- Implementation: [src/inference.cpp](src/inference.cpp), [src/scanner.cpp](src/scanner.cpp)
- Tshark protocol list: [tshark_protocol_code.txt](tshark_protocol_code.txt)

Notes
-----
- Link with `-lpcap` is required.
- The tool reads offline pcap files via libpcap and prints inferred protocol paths to stdout; redirect as needed.

Tshark supported protocols list
--------------------------------
Create/update `tshark_protocol_code.txt` with:

```bash
tshark -G fields | awk -F'\t' '$1=="P"{print $2 "\t" $3}' > tshark_protocol_code.txt
```

License
-------
No license specified — add a LICENSE file if you need explicit reuse terms.

