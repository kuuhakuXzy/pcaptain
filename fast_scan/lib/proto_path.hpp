#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "output.hpp"

// Builds a colon-separated protocol chain (e.g., "eth:ip:tcp:http")
class ProtoPath {
public:
    ProtoPath() = default;

    void clear() {
        _len = 0;
    }

    // Add a protocol name to the path, separated by colons
    void add(const char* s) {
        if (!s) return;

        // Add colon separator if not the first protocol
        if (_len && _len < MAX_LEN)
            _buf[_len++] = ':';

        // Append protocol name character by character
        while (*s && _len < MAX_LEN) {
            _buf[_len++] = *s++;
        }
    }

    // Write protocol path to output sink with newline
    void write_to(OutputSink& sink) const {
        if (_len == 0) return;
        sink.write(_buf, _len);
        sink.write("\n", 1);
    }

    bool empty() const { return _len == 0; }

    static constexpr size_t max_length() { return MAX_LEN; }

    // Copy colon-separated path into dst; returns length (no NUL if buffer full).
    size_t copy_to(char* dst, size_t cap) const {
        if (!dst || cap == 0) return 0;
        size_t n = (_len < cap - 1) ? _len : cap - 1;
        memcpy(dst, _buf, n);
        dst[n] = '\0';
        return n;
    }

private:
    static constexpr size_t MAX_LEN = 64;

    char _buf[MAX_LEN];
    uint8_t _len = 0;
};
