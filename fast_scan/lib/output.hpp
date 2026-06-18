#pragma once
#include <cstddef>
#include <cstdio>
#include <cstring>

// Abstract base class for output handling
class OutputSink {
public:
    virtual ~OutputSink() = default;
    virtual void write(const char* data, size_t len) = 0;
};

// Buffered output sink that writes to stdout in large chunks for performance
class BufferedStdoutSink : public OutputSink {
public:
    ~BufferedStdoutSink() {
        flush();
    }

    // Add data to buffer, flush if buffer would overflow
    void write(const char* data, size_t len) override {
        if (_len + len >= sizeof(_buf))
            flush();

        memcpy(_buf + _len, data, len);
        _len += len;
    }

    // Write buffered data to stdout
    void flush() {
        if (_len) {
            fwrite(_buf, 1, _len, stdout);
            _len = 0;
        }
    }

private:
    // 1MB buffer for efficient I/O
    char _buf[1 << 20];
    size_t _len = 0;
};
