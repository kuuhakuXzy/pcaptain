#include <pcap.h>
#include <cstring>
#include <iostream>
#include "scanner.hpp"

static void print_usage(const char* prog) {
    std::cerr
        << "Usage: " << prog << " [options] <pcap>\n"
        << "Options (combine as needed):\n"
        << "  --lines              Per-packet protocol paths (legacy)\n"
        << "  --summary            Single PCAPTAIN_SUMMARY line (default)\n"
        << "  --sample-every N     Process every Nth packet (1=all)\n"
        << "  --max-packets N      Stop after N packets seen\n"
        << "  --bpf FILTER         libpcap BPF filter expression\n"
        << "  --fingerprint        Emit PCAPTAIN_FP line for duplicate hints\n"
        << "  --ports-file PATH    Extra port→app lines: PORT l4proto appname\n";
}

int main(int argc, char* argv[]) {
    FastScanSettings settings;
    const char* pcap_path = nullptr;

    for (int i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "--lines") == 0) {
            settings.line_output = true;
            settings.summary_output = false;
        } else if (strcmp(argv[i], "--summary") == 0) {
            settings.summary_output = true;
            settings.line_output = false;
        } else if (strcmp(argv[i], "--fingerprint") == 0) {
            settings.emit_fingerprint = true;
        } else if (strcmp(argv[i], "--sample-every") == 0 && i + 1 < argc) {
            settings.sample_every = static_cast<uint32_t>(atoi(argv[++i]));
        } else if (strcmp(argv[i], "--max-packets") == 0 && i + 1 < argc) {
            settings.max_packets = static_cast<uint32_t>(atoi(argv[++i]));
        } else if (strcmp(argv[i], "--bpf") == 0 && i + 1 < argc) {
            settings.bpf_filter = argv[++i];
        } else if (strcmp(argv[i], "--ports-file") == 0 && i + 1 < argc) {
            settings.ports_file = argv[++i];
        } else if (argv[i][0] == '-') {
            std::cerr << "Unknown option: " << argv[i] << "\n";
            print_usage(argv[0]);
            return 1;
        } else {
            pcap_path = argv[i];
        }
    }

    if (!pcap_path) {
        print_usage(argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(pcap_path, errbuf);
    if (!handle) {
        std::cerr << errbuf << "\n";
        return 1;
    }

    if (settings.bpf_filter && settings.bpf_filter[0]) {
        struct bpf_program fp;
        if (pcap_compile(handle, &fp, settings.bpf_filter, 1, PCAP_NETMASK_UNKNOWN) != 0) {
            std::cerr << pcap_geterr(handle) << "\n";
            pcap_close(handle);
            return 1;
        }
        if (pcap_setfilter(handle, &fp) != 0) {
            std::cerr << pcap_geterr(handle) << "\n";
            pcap_freecode(&fp);
            pcap_close(handle);
            return 1;
        }
        pcap_freecode(&fp);
    }

    BufferedStdoutSink sink;
    ScanAccumulator accumulator;
    Scanner scanner(
        settings.line_output ? &sink : nullptr,
        settings.summary_output || settings.emit_fingerprint ? &accumulator : nullptr,
        settings);

    int dlt = pcap_datalink(handle);
    const u_char* packet;
    pcap_pkthdr* header;

    uint64_t packets_seen = 0;
    while (true) {
        int rc = pcap_next_ex(handle, &header, &packet);
        if (rc < 0) break;
        if (rc == 0) continue;

        if (settings.max_packets > 0 && packets_seen >= settings.max_packets) {
            break;
        }

        bool process = true;
        if (settings.sample_every > 1) {
            process = (packets_seen % settings.sample_every) == 0;
        }
        packets_seen += 1;

        if (process) {
            scanner.handle_packet(header, packet, dlt);
        }
    }

    accumulator.set_packets_seen(packets_seen);

    if (settings.summary_output) {
        accumulator.write_summary(sink, settings);
    }
    if (settings.emit_fingerprint) {
        accumulator.write_fingerprint(sink);
    }

    pcap_close(handle);
    return 0;
}
