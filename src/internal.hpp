#pragma once

#include "elf2epf/converter.hpp"
#include <algorithm>
#include <iomanip>
#include <limits>
#include <sstream>
#include <string_view>

namespace epf::detail {
inline constexpr std::uint64_t max_file = 256ull * 1024 * 1024;
inline constexpr std::uint64_t max_image = 16ull * 1024 * 1024 * 1024;
inline constexpr std::uint64_t max_entries = 1000000;
inline constexpr std::uint64_t max_name_bytes = 16384;
inline constexpr std::uint64_t max_total_names = 64ull * 1024 * 1024;
inline constexpr std::uint64_t max_segments = 4096;
inline constexpr std::size_t max_modules = 256;
[[noreturn]] inline void fail(const std::string& code, const std::string& message) {
    throw Error(code, message);
}
inline void require(bool condition, const std::string& message) {
    if (!condition) fail("E_FORMAT", message);
}
inline std::string hex(std::uint64_t v) {
    std::ostringstream out;
    out << "0x" << std::hex << v;
    return out.str();
}
inline std::uint64_t add(std::uint64_t a, std::uint64_t b) {
    require(b <= UINT64_MAX - a, "integer addition overflow");
    return a + b;
}
inline std::uint64_t mul(std::uint64_t a, std::uint64_t b) {
    require(a == 0 || b <= UINT64_MAX / a, "integer multiplication overflow");
    return a * b;
}
inline bool power2(std::uint64_t a) { return a && (a & (a - 1)) == 0; }
inline std::uint64_t down(std::uint64_t a, std::uint64_t align) { return a & ~(align - 1); }
inline std::uint64_t up(std::uint64_t a, std::uint64_t align) {
    require(power2(align), "alignment must be a nonzero power of two");
    return down(add(a, align - 1), align);
}
inline bool contains(std::uint64_t start, std::uint64_t size,
                     std::uint64_t at, std::uint64_t count) {
    return at >= start && at - start <= size && count <= size - (at - start);
}
inline bool overlaps(std::uint64_t a, std::uint64_t as,
                     std::uint64_t b, std::uint64_t bs) {
    return as && bs && a < add(b, bs) && b < add(a, as);
}
inline std::int64_t signed64(std::uint64_t value) {
    return value <= static_cast<std::uint64_t>(INT64_MAX)
        ? static_cast<std::int64_t>(value) : -1 - static_cast<std::int64_t>(~value);
}
inline std::uint64_t add_signed(std::uint64_t value, std::int64_t delta) {
    if (delta >= 0) return add(value, static_cast<std::uint64_t>(delta));
    const auto magnitude = static_cast<std::uint64_t>(-(delta + 1)) + 1;
    require(value >= magnitude, "relocation calculation underflow");
    return value - magnitude;
}
inline std::int64_t subtract_origin(std::int64_t value, std::uint64_t origin) {
    if (value >= 0 && static_cast<std::uint64_t>(value) >= origin)
        return static_cast<std::int64_t>(static_cast<std::uint64_t>(value) - origin);
    const auto magnitude = value >= 0 ? origin - static_cast<std::uint64_t>(value)
        : add(static_cast<std::uint64_t>(-(value + 1)) + 1, origin);
    require(magnitude <= (1ull << 63), "rebased relocation addend does not fit int64");
    return magnitude == (1ull << 63) ? INT64_MIN : -static_cast<std::int64_t>(magnitude);
}
class Reader {
public:
    explicit Reader(const Bytes& bytes) : data(bytes) {}
    const Bytes& data;
    void range(std::uint64_t offset, std::uint64_t size) const {
        require(offset <= data.size() && size <= data.size() - offset,
                "file range out of bounds at " + hex(offset) + " (size " + hex(size) + ")");
    }
    std::uint64_t u(std::uint64_t offset, unsigned size) const {
        range(offset, size);
        std::uint64_t value = 0;
        for (unsigned i = 0; i < size; ++i)
            value |= static_cast<std::uint64_t>(data[static_cast<std::size_t>(offset + i)]) << (8 * i);
        return value;
    }
    std::int64_t i64(std::uint64_t offset) const { return signed64(u(offset, 8)); }
    void zero(std::uint64_t offset, std::uint64_t size) const {
        range(offset, size);
        for (std::uint64_t i = 0; i < size; ++i)
            require(data[static_cast<std::size_t>(offset + i)] == 0,
                    "nonzero reserved/padding field at " + hex(offset + i));
    }
    std::string string(std::uint64_t start, std::uint64_t size, std::uint64_t index) const {
        range(start, size);
        require(index < size, "string offset outside string table");
        std::string result;
        for (auto i = index; i < size; ++i) {
            auto c = data[static_cast<std::size_t>(start + i)];
            if (!c) return result;
            if (result.size() >= max_name_bytes) fail("E_RESOURCE", "name/path exceeds 16 KiB resource limit");
            result.push_back(static_cast<char>(c));
        }
        fail("E_FORMAT", "unterminated string");
    }
};
inline void put(Bytes& out, std::uint64_t offset, std::uint64_t value, unsigned size) {
    require(offset <= out.size() && size <= out.size() - offset, "internal writer range error");
    for (unsigned i = 0; i < size; ++i)
        out[static_cast<std::size_t>(offset + i)] = static_cast<std::uint8_t>(value >> (i * 8));
}
inline std::uint64_t reserve(Bytes& out, std::uint64_t size, std::uint64_t align = 8) {
    const auto offset = up(out.size(), align);
    const auto end = add(offset, size);
    require(end <= max_file, "file exceeds 256 MiB resource limit");
    out.resize(static_cast<std::size_t>(end), 0);
    return offset;
}
inline std::uint64_t append(Bytes& out, const Bytes& data, std::uint64_t align = 8) {
    auto offset = reserve(out, data.size(), align);
    std::copy(data.begin(), data.end(), out.begin() + static_cast<std::ptrdiff_t>(offset));
    return offset;
}
inline void library_name(const std::string& name) {
    require(!name.empty() && name != "." && name != ".." &&
            name.find_first_of("/\\:\0", 0, 4) == std::string::npos,
            "library name must be a single filename: " + name);
}
inline std::uint32_t relocation_width(RelocType type) {
    switch (type) {
    case RelocType::none: return 0;
    case RelocType::abs32: case RelocType::pcrel32: case RelocType::relative32: return 4;
    case RelocType::abs64: case RelocType::relative64: return 8;
    }
    fail("E_UNSUPPORTED", "unknown EPF relocation type");
}

struct ElfSegment {
    std::uint32_t type = 0, flags = 0;
    std::uint64_t offset = 0, vaddr = 0, filesz = 0, memsz = 0, align = 1;
};
struct ElfSymbol {
    std::string name;
    std::uint64_t value = 0, size = 0;
    std::uint16_t section = 0;
    std::uint8_t binding = 0, type = 0, visibility = 0;
};
struct ElfRelocation {
    std::uint64_t offset = 0;
    std::int64_t addend = 0;
    std::uint32_t symbol = 0, type = 0;
};
struct ElfFile {
    const Bytes* bytes = nullptr;
    std::uint16_t type = 0;
    std::uint64_t entry = 0;
    std::vector<ElfSegment> loads, relro_segments;
    std::vector<ElfSymbol> symbols;
    std::vector<ElfRelocation> relocations;
    std::map<std::uint64_t, std::uint64_t> tags;
    std::vector<std::string> needed;
    std::optional<std::string> soname;
    bool interpreter = false, marked_pie = false;
    std::uint64_t file_at(std::uint64_t va, std::uint64_t size) const;
    bool code_at(std::uint64_t va) const;
};
ElfFile read_elf(const Bytes& bytes);
void encode_header(Bytes& out, const Header& h, std::size_t segment_count);
void encode_segment(Bytes& out, std::uint64_t at, const Segment& segment);
} // namespace epf::detail
