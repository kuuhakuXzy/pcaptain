#pragma once
#include <pcap.h>
#include "inference.hpp"
#include "output.hpp"
#include "proto_path.hpp"

class Scanner {
public:
    explicit Scanner(OutputSink& sink);

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
                   const u_char* l4,
                   size_t caplen,
                   size_t offset,
                   ProtoPath& path);

    PortTable _ports;
    OutputSink& _sink;
};
