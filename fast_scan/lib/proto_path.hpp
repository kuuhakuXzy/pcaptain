#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "output.hpp"

class ProtoPath {
public:
    ProtoPath() = default;

    void clear() {
        _len = 0;
    }

    void add(const char* s) {
        if (!s) return;

        if (_len && _len < MAX_LEN)
            _buf[_len++] = ':';

        while (*s && _len < MAX_LEN) {
            _buf[_len++] = *s++;
        }
    }

    void write_to(OutputSink& sink) const {
        if (_len == 0) return;
        sink.write(_buf, _len);
        sink.write("\n", 1);
    }

    bool empty() const { return _len == 0; }

private:
    static constexpr size_t MAX_LEN = 64;

    char _buf[MAX_LEN];
    uint8_t _len = 0;
};
