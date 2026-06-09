#include "scanner.hpp"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>

#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif

Scanner::Scanner(OutputSink* line_sink,
                 ScanAccumulator* accumulator,
                 const FastScanSettings& settings)
    : _line_sink(line_sink),
      _accumulator(accumulator),
      _settings(settings)
{
    init_port_table(_ports);
    if (_settings.ports_file) {
        apply_ports_file(_ports, _settings.ports_file);
    }
}

bool Scanner::handle_l4(uint8_t proto,
                        const u_char* packet,
                        size_t caplen,
                        size_t offset,
                        ProtoPath& path,
                        uint16_t& sport,
                        uint16_t& dport)
{
    sport = 0;
    dport = 0;
    L4Proto p;
    const char* pname = nullptr;

    if (proto == IPPROTO_TCP) {
        if (offset + sizeof(tcphdr) > caplen) return false;
        auto* tcp = (const tcphdr*)(packet + offset);
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        p = L4Proto::TCP;
        pname = "tcp";
    } else if (proto == IPPROTO_UDP) {
        if (offset + sizeof(udphdr) > caplen) return false;
        auto* udp = (const udphdr*)(packet + offset);
        sport = ntohs(udp->uh_sport);
        dport = ntohs(udp->uh_dport);
        p = L4Proto::UDP;
        pname = "udp";
    } else if (proto == IPPROTO_SCTP || proto == 33) {
        if (offset + 4 > caplen) return false;
        sport = ntohs(*(uint16_t*)(packet + offset));
        dport = ntohs(*(uint16_t*)(packet + offset + 2));
        p = (proto == IPPROTO_SCTP) ? L4Proto::SCTP : L4Proto::DCCP;
        pname = (proto == IPPROTO_SCTP) ? "sctp" : "dccp";
    } else {
        return false;
    }

    path.add(pname);

    const PortInfo* info = _ports.lookup(sport, dport);
    if (info) {
        const char* app = info->get(p);
        if (app) path.add(app);
    }

    return true;
}

void Scanner::handle_ipv4(const pcap_pkthdr* hdr,
                          const u_char* packet,
                          size_t offset,
                          uint64_t packet_index,
                          ProtoPath& path)
{
    if (offset + sizeof(ip) > hdr->caplen) return;

    path.add("ip");

    const ip* iphdr = (const ip*)(packet + offset);
    size_t ip_len = iphdr->ip_hl * 4;
    if (ip_len < 20) return;

    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &iphdr->ip_src, src, sizeof(src))) return;
    if (!inet_ntop(AF_INET, &iphdr->ip_dst, dst, sizeof(dst))) return;

    offset += ip_len;
    if (offset >= hdr->caplen) {
        if (_accumulator) {
            _accumulator->record_endpoints(
                src, dst, 0, 0, false, packet_index, _settings);
        }
        return;
    }

    uint16_t sport = 0;
    uint16_t dport = 0;
    bool has_l4 = handle_l4(iphdr->ip_p, packet, hdr->caplen, offset, path, sport, dport);

    if (_accumulator) {
        _accumulator->record_endpoints(
            src, dst, sport, dport, has_l4, packet_index, _settings);
    }
}

void Scanner::handle_ipv6(const pcap_pkthdr* hdr,
                          const u_char* packet,
                          size_t offset,
                          uint64_t packet_index,
                          ProtoPath& path)
{
    if (offset + sizeof(ip6_hdr) > hdr->caplen) return;

    path.add("ipv6");

    const ip6_hdr* ip6 = (const ip6_hdr*)(packet + offset);

    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];
    if (!inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src))) return;
    if (!inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst))) return;

    offset += sizeof(ip6_hdr);
    if (offset >= hdr->caplen) {
        if (_accumulator) {
            _accumulator->record_endpoints(
                src, dst, 0, 0, false, packet_index, _settings);
        }
        return;
    }

    uint16_t sport = 0;
    uint16_t dport = 0;
    bool has_l4 = handle_l4(ip6->ip6_nxt, packet, hdr->caplen, offset, path, sport, dport);

    if (_accumulator) {
        _accumulator->record_endpoints(
            src, dst, sport, dport, has_l4, packet_index, _settings);
    }
}

void Scanner::handle_packet(const pcap_pkthdr* hdr,
                            const u_char* packet,
                            int dlt,
                            uint64_t packet_index)
{
    ProtoPath path;

    switch (dlt) {
        case DLT_EN10MB: {
            if (hdr->caplen < sizeof(ether_header)) {
                return;
            }

            path.add("eth");

            auto* eth = (const ether_header*)packet;
            uint16_t type = ntohs(eth->ether_type);
            size_t offset = sizeof(ether_header);

            if (type == ETHERTYPE_IP)
                handle_ipv4(hdr, packet, offset, packet_index, path);
            else if (type == ETHERTYPE_IPV6)
                handle_ipv6(hdr, packet, offset, packet_index, path);
            break;
        }

        case DLT_LINUX_SLL: {
            if (hdr->caplen < 16) {
                return;
            }
            uint16_t type = (packet[14] << 8) | packet[15];
            size_t offset = 16;
            if (type == 0x0800)
                handle_ipv4(hdr, packet, offset, packet_index, path);
            else if (type == 0x86DD)
                handle_ipv6(hdr, packet, offset, packet_index, path);
            break;
        }

        case DLT_RAW: {
            uint8_t v = packet[0] >> 4;
            if (v == 4)
                handle_ipv4(hdr, packet, 0, packet_index, path);
            else if (v == 6)
                handle_ipv6(hdr, packet, 0, packet_index, path);
            break;
        }
    }

    if (path.empty()) return;

    if (_accumulator) {
        _accumulator->record_packet(path);
    }
    if (_line_sink && _settings.line_output) {
        path.write_to(*_line_sink);
    }
}
