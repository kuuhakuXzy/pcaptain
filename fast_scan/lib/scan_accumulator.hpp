#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>

#include "output.hpp"
#include "proto_path.hpp"
#include "scan_settings.hpp"

class ScanAccumulator {
public:
    void record_packet(const ProtoPath& path);
    void set_packets_seen(uint64_t n) { _packets_seen = n; }

    uint64_t packets_seen() const { return _packets_seen; }
    uint64_t packets_scanned() const { return _packets_scanned; }
    const std::unordered_map<std::string, uint64_t>& protocol_counts() const {
        return _protocol_counts;
    }

    void write_summary(OutputSink& sink, const FastScanSettings& settings) const;
    void write_fingerprint(OutputSink& sink) const;

private:
    uint64_t _packets_seen = 0;
    uint64_t _packets_scanned = 0;
    std::unordered_map<std::string, uint64_t> _protocol_counts;
};
