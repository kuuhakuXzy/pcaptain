#pragma once
#include <cstdint>
#include <initializer_list>
#include <array>
#include <cstddef>

// Transport layer (Layer 4) protocol types
enum class L4Proto : uint8_t {
    TCP = 0,
    UDP,
    SCTP,
    DCCP,
    COUNT
};

// Maps L4 protocols to application protocol names for a specific port
class PortInfo {
public:
    PortInfo();

    void set(L4Proto proto, const char* app);
    const char* get(L4Proto proto) const;
    bool valid() const;

private:
    static constexpr size_t idx(L4Proto proto) {
        return static_cast<size_t>(proto);
    }

    std::array<const char*, static_cast<size_t>(L4Proto::COUNT)> _apps{};
    bool _valid = false;
};

// Port number to application protocol mapping table (65536 entries)
class PortTable {
public:
    // Register an application protocol for a specific port and L4 protocols
    void set(uint16_t port,
             std::initializer_list<L4Proto> protos,
             const char* app);

    // Find application protocol using source and destination ports
    const PortInfo* lookup(uint16_t sport, uint16_t dport) const;

private:
    PortInfo _table[65536];
};

// Populate port table with well-known port assignments (HTTP, SSH, DNS, etc.)
void init_port_table(PortTable& ports);
