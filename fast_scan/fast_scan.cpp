#include <pcap.h>
#include <iostream>
#include "scanner.hpp"

int main(int argc, char* argv[]) {
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

    BufferedStdoutSink sink;
    Scanner scanner(sink);
    int dlt = pcap_datalink(handle);

    const u_char* packet;
    pcap_pkthdr* header;

    while (pcap_next_ex(handle, &header, &packet) > 0) {
        scanner.handle_packet(header, packet, dlt);
    }

    pcap_close(handle);
    return 0;
}
