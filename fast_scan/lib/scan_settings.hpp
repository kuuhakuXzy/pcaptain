#pragma once

#include <cstdint>

// User-selectable fastscan behavior (CLI flags map 1:1 to backend scan options).
struct FastScanSettings {
    bool line_output = false;
    bool summary_output = true;
    bool emit_fingerprint = false;
    uint32_t sample_every = 0;
    uint32_t max_packets = 0;
    const char* bpf_filter = nullptr;
    const char* ports_file = nullptr;
};
