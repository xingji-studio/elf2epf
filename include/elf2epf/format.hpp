#pragma once

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <vector>

namespace epf {
using Bytes = std::vector<std::uint8_t>;
inline constexpr std::uint64_t no_entry = std::numeric_limits<std::uint64_t>::max();
inline constexpr std::uint32_t required = 0x80000000u;
inline constexpr std::uint32_t readable = 1, writable = 2, executable = 4, pie = 1;
inline constexpr std::uint64_t feature_runtime_reloc = 1, feature_dynamic_link = 2;
inline constexpr std::uint64_t feature_tls = 4, feature_relro = 8;

enum class FileType : std::uint16_t { exec = 2, shared = 3 };
enum class SegmentType : std::uint32_t {
    null = 0, load = 1, dynamic = 2, interp = 3, tls = 4, relro = 5, note = 6
};
enum class RelocType : std::uint32_t {
    none = 0, abs32 = 1, abs64 = 2, pcrel32 = 3, relative32 = 4, relative64 = 5
};
enum class Domain : std::uint8_t { undef = 0, section = 1, image = 2, absolute = 3, tls = 4 };

struct Header {
    FileType type = FileType::exec;
    std::uint16_t os_abi = 0, abi_version = 1;
    std::uint32_t flags = 0, arch_flags = 0;
    std::uint64_t features = 0, image_base = 0, entry_rva = no_entry, image_size = 0;
    std::uint64_t map_align = 4096, segment_table_offset = 128, file_size = 0;
};

struct Segment {
    SegmentType type = SegmentType::null;
    std::uint32_t flags = 0;
    std::uint64_t file_offset = 0, rva = 0, file_size = 0, mem_size = 0, align = 1;
};
struct Symbol {
    std::uint32_t name_offset = 0;
    std::uint64_t value = 0, size = 0;
    std::uint8_t binding = 0, type = 0, visibility = 0;
    Domain domain = Domain::undef;
    std::string name;
};
struct Relocation {
    std::uint64_t offset = 0;
    std::int64_t addend = 0;
    std::uint32_t symbol_index = 0;
    RelocType type = RelocType::none;
};
struct Image {
    Header header;
    Bytes bytes;
    std::vector<Segment> segments;
    std::vector<Symbol> symbols;
    std::vector<Relocation> relocations;
    std::vector<std::string> needed;
    std::optional<std::string> soname, interpreter;
    std::vector<std::uint64_t> init, fini;
};
} // namespace epf
