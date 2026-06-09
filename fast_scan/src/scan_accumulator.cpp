#include "scan_accumulator.hpp"

#include <sstream>

void ScanAccumulator::record_packet(const ProtoPath& path) {
    _packets_seen += 1;
    if (path.empty()) return;

    _packets_scanned += 1;

    char buf[ProtoPath::max_length() + 1];
    size_t len = path.copy_to(buf, sizeof(buf));
    if (len == 0) return;

    std::unordered_set<std::string> seen;
    size_t start = 0;
    for (size_t i = 0; i <= len; ++i) {
        if (i == len || buf[i] == ':') {
            if (i > start) {
                buf[i] = '\0';
                seen.emplace(buf + start);
            }
            start = i + 1;
        }
    }

    for (const auto& proto : seen) {
        _protocol_counts[proto] += 1;
    }
}

static void append_kv_list(
    std::ostringstream& oss,
    const std::unordered_map<std::string, uint64_t>& counts)
{
    bool first = true;
    for (const auto& kv : counts) {
        if (!first) oss << ',';
        first = false;
        oss << kv.first << ':' << kv.second;
    }
}

void ScanAccumulator::write_summary(OutputSink& sink, const FastScanSettings& settings) const {
    std::ostringstream oss;
    oss << "PCAPTAIN_SUMMARY";
    oss << " packets_seen=" << _packets_seen;
    oss << " packets_scanned=" << _packets_scanned;
    if (settings.sample_every > 0) {
        oss << " sample_every=" << settings.sample_every;
    }
    if (settings.max_packets > 0) {
        oss << " max_packets=" << settings.max_packets;
    }
    if (settings.bpf_filter) {
        oss << " bpf=1";
    }
    oss << " protocols=";
    append_kv_list(oss, _protocol_counts);
    std::string line = oss.str();
    sink.write(line.c_str(), line.size());
    sink.write("\n", 1);
}

void ScanAccumulator::write_fingerprint(OutputSink& sink) const {
    std::ostringstream oss;
    oss << "PCAPTAIN_FP v1";
    for (const auto& kv : _protocol_counts) {
        oss << '|' << kv.first << '=' << kv.second;
    }
    std::string line = oss.str();
    sink.write(line.c_str(), line.size());
    sink.write("\n", 1);
}
