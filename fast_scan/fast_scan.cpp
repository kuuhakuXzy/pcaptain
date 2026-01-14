#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include <iostream>
#include "well_known_port.h"
#include <cstring>


static char OUT_BUF[1 << 20]; 
static size_t OUT_LEN = 0;

inline void flush_out() {
    fwrite(OUT_BUF, 1, OUT_LEN, stdout);
    OUT_LEN = 0;
}

struct ProtoPath {
    char buf[64];
    uint8_t len = 0;

    inline void add(const char* s) {
        if (len) buf[len++] = ':';
        while (*s) buf[len++] = *s++;
    }
};

void handle_l4(
    uint8_t proto,
    const u_char* l4,
    size_t caplen,
    size_t offset,
    ProtoPath& path
) {
    uint16_t sport, dport;
    uint8_t bit;

    if (proto == IPPROTO_TCP) {
        if (offset + sizeof(tcphdr) > caplen) return;
        auto* tcp = (const tcphdr*)l4;
        sport = ntohs(tcp->th_sport);
        dport = ntohs(tcp->th_dport);
        bit = BIT_TCP;
        path.add("tcp");
    }
    else if (proto == IPPROTO_UDP) {
        if (offset + sizeof(udphdr) > caplen) return;
        auto* udp = (const udphdr*)l4;
        sport = ntohs(udp->uh_sport);
        dport = ntohs(udp->uh_dport);
        bit = BIT_UDP;
        path.add("udp");
    }
    else if (proto == IPPROTO_SCTP || proto == 33) {
        if (offset + 4 > caplen) return;
        sport = ntohs(*(uint16_t*)l4);
        dport = ntohs(*(uint16_t*)(l4 + 2));
        bit = (proto == IPPROTO_SCTP) ? BIT_SCTP : BIT_DCCP;
        path.add(proto == IPPROTO_SCTP ? "sctp" : "dccp");
    }
    else return;

    const PortInfo* info = lookup_port(sport, dport);
    if (!info || !(info->bits & bit))
        return;
    const char* app = lookup_app(info, bit);

    if (!app) return;

    path.add(app);
}


void handle_ipv4_at(
    const pcap_pkthdr* hdr,
    const u_char* packet,
    size_t offset,
    ProtoPath& path
) {
    if (offset + sizeof(ip) > hdr->caplen)
        return;

    const ip* iphdr =
        reinterpret_cast<const ip*>(packet + offset);

    size_t ip_len = iphdr->ip_hl * 4;
    if (ip_len < 20)
        return;

    path.add("ip");

    offset += ip_len;
    if (offset >= hdr->caplen)
        return;

    handle_l4(iphdr->ip_p, packet + offset, hdr->caplen, offset, path);
}


bool walk_ipv6_headers(
    const u_char* packet,
    size_t caplen,
    size_t& offset,
    uint8_t& next
) {
    while (true) {
        switch (next) {
            case IPPROTO_HOPOPTS:
            case IPPROTO_ROUTING:
            case IPPROTO_DSTOPTS: {
                if (offset + 2 > caplen) return false;
                uint8_t hdrlen = packet[offset + 1];
                next = packet[offset];
                offset += (hdrlen + 1) * 8;
                break;
            }
            case IPPROTO_FRAGMENT:
                if (offset + 8 > caplen) return false;
                next = packet[offset];
                offset += 8;
                break;
            default:
                return true;
        }

        if (offset >= caplen)
            return false;
    }
}

void handle_ipv6_at(
    const pcap_pkthdr* hdr,
    const u_char* packet,
    size_t offset,
    ProtoPath& path
) {
    if (offset + sizeof(ip6_hdr) > hdr->caplen)
        return;

    path.add("ipv6");

    const ip6_hdr* ip6 =
        reinterpret_cast<const ip6_hdr*>(packet + offset);

    uint8_t next = ip6->ip6_nxt;
    offset += sizeof(ip6_hdr);

    if (!walk_ipv6_headers(packet, hdr->caplen, offset, next))
        return;

    handle_l4(next, packet + offset, hdr->caplen, offset, path);
}

void handle_packet(
    const pcap_pkthdr* hdr,
    const u_char* packet,
    int dlt
) {
    ProtoPath path;
    size_t offset = 0;

    switch (dlt) {

        case DLT_EN10MB: {
            if (hdr->caplen < sizeof(ether_header))
                return;

            path.add("eth");

            const ether_header* eth =
                reinterpret_cast<const ether_header*>(packet);

            uint16_t type = ntohs(eth->ether_type);
            offset = sizeof(ether_header);

            if (type == ETHERTYPE_IP)
                handle_ipv4_at(hdr, packet, offset, path);
            else if (type == ETHERTYPE_IPV6)
                handle_ipv6_at(hdr, packet, offset, path);
            break;
        }

        case DLT_RAW: {
            uint8_t v = packet[0] >> 4;
            if (v == 4)
                handle_ipv4_at(hdr, packet, 0, path);
            else if (v == 6)
                handle_ipv6_at(hdr, packet, 0, path);
            break;
        }

        default:
            return;
    }

    if (path.len) {
        if (OUT_LEN + path.len + 1 >= sizeof(OUT_BUF))
            flush_out();

        memcpy(OUT_BUF + OUT_LEN, path.buf, path.len);
        OUT_LEN += path.len;
        OUT_BUF[OUT_LEN++] = '\n';
    }
}



int main(int argc, char* argv[]) {
    init_port_table();
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <pcap>\n";
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (!handle) {
        std::cerr << errbuf << "\n";
        return 1;
    }

    const u_char* packet;
    pcap_pkthdr* header;
    int dlt = pcap_datalink(handle);

    while (pcap_next_ex(handle, &header, &packet) > 0) {
        handle_packet(header, packet, dlt);
    }

    pcap_close(handle);
    flush_out();
    return 0;
}
