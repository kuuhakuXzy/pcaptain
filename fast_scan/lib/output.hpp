#pragma once
#include <cstddef>
#include <cstdio>
#include <cstring>

class OutputSink {
public:
    virtual ~OutputSink() = default;
    virtual void write(const char* data, size_t len) = 0;
};

class BufferedStdoutSink : public OutputSink {
public:
    ~BufferedStdoutSink() {
        flush();
    }

    void write(const char* data, size_t len) override {
        if (_len + len >= sizeof(_buf))
            flush();

        memcpy(_buf + _len, data, len);
        _len += len;
    }

    void flush() {
        if (_len) {
            fwrite(_buf, 1, _len, stdout);
            _len = 0;
        }
    }

private:
    char _buf[1 << 20];
    size_t _len = 0;
};
