#include "scanner.hpp"

#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <cstring>
#include <iostream>


Scanner::Scanner(OutputSink& sink) : _sink(sink)
{
    init_port_table(_ports);
}

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
        if (offset + sizeof(tcphdr) > caplen) return;
        auto* tcp = (const tcphdr*)l4;
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

    const PortInfo* info = _ports.lookup(sport, dport);
    if (!info) return;

    const char* app = info->get(p);
    if (!app) return;

    path.add(app);
}

void Scanner::handle_ipv4(const pcap_pkthdr* hdr,
                          const u_char* packet,
                          size_t offset,
                          ProtoPath& path)
{
    if (offset + sizeof(ip) > hdr->caplen) return;

    path.add("ip");

    const ip* iphdr = (const ip*)(packet + offset);
    size_t ip_len = iphdr->ip_hl * 4;
    if (ip_len < 20) return;

    offset += ip_len;
    if (offset >= hdr->caplen) return;

    handle_l4(iphdr->ip_p, packet + offset, hdr->caplen, offset, path);
}

void Scanner::handle_ipv6(const pcap_pkthdr* hdr,
                          const u_char* packet,
                          size_t offset,
                          ProtoPath& path)
{
    if (offset + sizeof(ip6_hdr) > hdr->caplen) return;

    path.add("ipv6");

    const ip6_hdr* ip6 = (const ip6_hdr*)(packet + offset);
    offset += sizeof(ip6_hdr);

    handle_l4(ip6->ip6_nxt, packet + offset, hdr->caplen, offset, path);
}

void Scanner::handle_packet(const pcap_pkthdr* hdr,
                            const u_char* packet,
                            int dlt)
{
    ProtoPath path;

    switch (dlt) {
        case DLT_EN10MB: {
            if (hdr->caplen < sizeof(ether_header)) return;

            path.add("eth");

            auto* eth = (const ether_header*)packet;
            uint16_t type = ntohs(eth->ether_type);
            size_t offset = sizeof(ether_header);

            if (type == ETHERTYPE_IP)
                handle_ipv4(hdr, packet, offset, path);
            else if (type == ETHERTYPE_IPV6)
                handle_ipv6(hdr, packet, offset, path);
            break;
        }

        case DLT_RAW: {
            uint8_t v = packet[0] >> 4;
            if (v == 4)
                handle_ipv4(hdr, packet, 0, path);
            else if (v == 6)
                handle_ipv6(hdr, packet, 0, path);
            break;
        }
    }

    if (!path.empty()) {
        path.write_to(_sink);
    }
}
