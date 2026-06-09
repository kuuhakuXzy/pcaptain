#pragma once
#include <pcap.h>
#include "inference.hpp"
#include "output.hpp"
#include "proto_path.hpp"
#include "scan_accumulator.hpp"
#include "scan_settings.hpp"

class Scanner {
public:
    Scanner(OutputSink* line_sink, ScanAccumulator* accumulator, const FastScanSettings& settings);

    void handle_packet(const pcap_pkthdr* hdr,
                       const u_char* packet,
                       int dlt);

private:
    void handle_ipv4(const pcap_pkthdr* hdr,
                     const u_char* packet,
                     size_t offset,
                     ProtoPath& path);

    void handle_ipv6(const pcap_pkthdr* hdr,
                     const u_char* packet,
                     size_t offset,
                     ProtoPath& path);

    void handle_l4(uint8_t proto,
                   const u_char* packet,
                   size_t caplen,
                   size_t offset,
                   ProtoPath& path);

    PortTable _ports;
    OutputSink* _line_sink;
    ScanAccumulator* _accumulator;
    FastScanSettings _settings;
};
