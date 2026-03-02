#include "scanner.hpp"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>


// Initialize scanner with output sink and populate port-to-protocol mapping table
Scanner::Scanner(OutputSink& sink) : _sink(sink)
{
    init_port_table(_ports);
}

// Parse transport layer (L4) protocol and identify application protocol from port numbers
void Scanner::handle_l4(uint8_t proto,
                        const u_char* l4,
                        size_t caplen,
                        size_t offset,
                        ProtoPath& path)
{
    uint16_t sport, dport;
    L4Proto p;
    const char* pname;

    if (proto == IPPROTO_TCP) {
        // Ensure TCP header fits within captured data
        if (offset + sizeof(tcphdr) > caplen) return;
        auto* tcp = (const tcphdr*)l4;
        // ntohs() converts network byte order (big-endian) to host byte order
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        p = L4Proto::TCP;
        pname = "tcp";
    }
    else if (proto == IPPROTO_UDP) {
        if (offset + sizeof(udphdr) > caplen) return;
        auto* udp = (const udphdr*)l4;
        sport = ntohs(udp->uh_sport);
        dport = ntohs(udp->uh_dport);
        p = L4Proto::UDP;
        pname = "udp";
    }
    else if (proto == IPPROTO_SCTP || proto == 33) {
        if (offset + 4 > caplen) return;
        sport = ntohs(*(uint16_t*)l4);
        dport = ntohs(*(uint16_t*)(l4 + 2));
        p = (proto == IPPROTO_SCTP) ? L4Proto::SCTP : L4Proto::DCCP;
        pname = (proto == IPPROTO_SCTP) ? "sctp" : "dccp";
    }
    else {
        return;
    }

    path.add(pname);

    // Look up application protocol based on source and destination ports
    const PortInfo* info = _ports.lookup(sport, dport);
    if (!info) return;

    const char* app = info->get(p);
    if (!app) return;

    // Add application protocol to path (e.g., "http", "dns", "ssh")
    path.add(app);
}

// Parse IPv4 header and delegate to L4 handler
void Scanner::handle_ipv4(const pcap_pkthdr* hdr,
                          const u_char* packet,
                          size_t offset,
                          ProtoPath& path)
{
    if (offset + sizeof(ip) > hdr->caplen) return;

    path.add("ip");

    const ip* iphdr = (const ip*)(packet + offset);
    // IP header length is in 32-bit words, multiply by 4 for bytes
    size_t ip_len = iphdr->ip_hl * 4;
    // Minimum IPv4 header is 20 bytes
    if (ip_len < 20) return;

    offset += ip_len;
    if (offset >= hdr->caplen) return;

    handle_l4(iphdr->ip_p, packet + offset, hdr->caplen, offset, path);
}

// Parse IPv6 header and delegate to L4 handler
void Scanner::handle_ipv6(const pcap_pkthdr* hdr,
                          const u_char* packet,
                          size_t offset,
                          ProtoPath& path)
{
    if (offset + sizeof(ip6_hdr) > hdr->caplen) return;

    path.add("ipv6");

    const ip6_hdr* ip6 = (const ip6_hdr*)(packet + offset);
    // IPv6 header is fixed 40 bytes (unlike IPv4 which has variable length)
    offset += sizeof(ip6_hdr);

    handle_l4(ip6->ip6_nxt, packet + offset, hdr->caplen, offset, path);
}

// Entry point for packet processing: determines data link type and starts protocol chain
void Scanner::handle_packet(const pcap_pkthdr* hdr,
                            const u_char* packet,
                            int dlt)
{
    ProtoPath path;

    switch (dlt) {
        // DLT_EN10MB is Ethernet (10 Megabit)
        case DLT_EN10MB: {
            if (hdr->caplen < sizeof(ether_header)) return;

            path.add("eth");

            auto* eth = (const ether_header*)packet;
            // Convert Ethernet type field from network to host byte order
            uint16_t type = ntohs(eth->ether_type);
            size_t offset = sizeof(ether_header);

            if (type == ETHERTYPE_IP)
                handle_ipv4(hdr, packet, offset, path);
            else if (type == ETHERTYPE_IPV6)
                handle_ipv6(hdr, packet, offset, path);
            break;
        }

        // DLT_RAW is raw IP packets (no link layer header)
        case DLT_RAW: {
            // First 4 bits of IP header contain version number (4 or 6)
            uint8_t v = packet[0] >> 4;
            if (v == 4)
                handle_ipv4(hdr, packet, 0, path);
            else if (v == 6)
                handle_ipv6(hdr, packet, 0, path);
            break;
        }
    }

    // Output the protocol chain (e.g., "eth:ip:tcp:http")
    if (!path.empty()) {
        path.write_to(_sink);
    }
}
