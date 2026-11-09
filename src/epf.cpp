#include "internal.hpp"
#include <deque>
#include <functional>
#include <set>
#include <unordered_map>

namespace epf::detail {
void encode_header(Bytes& out, const Header& h, std::size_t count) {
    put(out, 0, 0x46504524, 4); put(out, 4, 1, 1); put(out, 6, 8, 1); put(out, 7, 1, 1);
    put(out, 8, static_cast<std::uint16_t>(h.type), 2); put(out, 10, 62, 2);
    put(out, 12, h.os_abi, 2); put(out, 14, h.abi_version, 2);
    put(out, 16, h.flags, 4); put(out, 20, 128, 4); put(out, 24, h.features, 8);
    put(out, 32, h.image_base, 8); put(out, 40, h.entry_rva, 8); put(out, 48, h.image_size, 8);
    put(out, 56, h.segment_table_offset, 8); put(out, 72, h.file_size, 8);
    put(out, 80, count, 4); put(out, 92, 64, 2); put(out, 94, 64, 2);
    put(out, 96, h.map_align, 8); put(out, 104, h.arch_flags, 4);
}
void encode_segment(Bytes& out, std::uint64_t at, const Segment& s) {
    put(out, at, static_cast<std::uint32_t>(s.type), 4); put(out, at + 4, s.flags, 4);
    put(out, at + 8, s.file_offset, 8); put(out, at + 16, s.rva, 8);
    put(out, at + 24, s.file_size, 8); put(out, at + 32, s.mem_size, 8); put(out, at + 40, s.align, 8);
}
} // namespace epf::detail

namespace epf {
using namespace detail;
namespace {
struct Span { std::uint64_t at, size; };
const Segment* memory_load(const Image& image, std::uint64_t at, std::uint64_t size) {
    for (const auto& s : image.segments)
        if (s.type == SegmentType::load && contains(s.rva, s.mem_size, at, size)) return &s;
    return nullptr;
}
std::uint64_t file_at(const Image& image, std::uint64_t at, std::uint64_t size) {
    for (const auto& s : image.segments)
        if (s.type == SegmentType::load && contains(s.rva, s.file_size, at, size))
            return add(s.file_offset, at - s.rva);
    fail("E_FORMAT", "EPF RVA is not in initialized LOAD content at " + hex(at));
}
bool code_at(const Image& image, std::uint64_t at) {
    for (const auto& s : image.segments)
        if (s.type == SegmentType::load && (s.flags & executable) && contains(s.rva, s.file_size, at, 1))
            return true;
    return false;
}
bool is_relro(const Image& image, std::uint64_t at, std::uint64_t size) {
    for (const auto& s : image.segments)
        if (s.type == SegmentType::relro && contains(s.rva, s.mem_size, at, size)) return true;
    return false;
}
std::string quoted(const std::string& value) {
    std::ostringstream out; out << '"';
    for (auto c : value) {
        const auto byte = static_cast<unsigned char>(c);
        if (c == '\\' || c == '"') out << '\\' << c;
        else if (byte < 32 || byte == 127) out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << unsigned(byte) << std::dec;
        else out << c;
    }
    out << '"'; return out.str();
}
const char* segment_name(SegmentType type) {
    switch (type) {
    case SegmentType::null: return "NULL";
    case SegmentType::load: return "LOAD";
    case SegmentType::dynamic: return "DYNAMIC";
    case SegmentType::interp: return "INTERP";
    case SegmentType::tls: return "TLS";
    case SegmentType::relro: return "RELRO";
    case SegmentType::note: return "NOTE";
    }
    return "UNKNOWN";
}
} // namespace

Image decode(const Bytes& bytes) {
    Reader r(bytes);
    require(bytes.size() <= max_file, "EPF exceeds file resource limit");
    r.range(0, 128);
    require(r.u(0, 4) == 0x46504524, "input is not EPF ($EPF)");
    if (r.u(4, 1) != 1 || r.u(5, 1) != 0)
        fail("E_UNSUPPORTED", "this tool supports EPF version 1.0");
    if (r.u(6, 1) != 8 || r.u(7, 1) != 1 || r.u(10, 2) != 62)
        fail("E_UNSUPPORTED", "this tool supports little-endian x86-64 EPF with 8-byte addresses");
    const auto type = r.u(8, 2);
    if (type != 2 && type != 3) fail("E_UNSUPPORTED", "only EXEC and SHARED EPF images are supported");
    require(r.u(20, 4) == 128 && r.u(92, 2) == 64 && r.u(94, 2) == 64,
            "invalid EPF v1.0 structure sizes");
    if (r.u(64, 8) || r.u(84, 4))
        fail("E_UNSUPPORTED", "this validator currently supports sectionless EPF images");
    require(r.u(88, 4) == 0, "sectionless EPF must have shstr_index zero");
    r.zero(108, 20);
    Image image;
    auto& h = image.header;
    h.type = static_cast<FileType>(type);
    h.os_abi = static_cast<std::uint16_t>(r.u(12, 2)); h.abi_version = static_cast<std::uint16_t>(r.u(14, 2));
    h.flags = static_cast<std::uint32_t>(r.u(16, 4)); h.features = r.u(24, 8);
    h.image_base = r.u(32, 8); h.entry_rva = r.u(40, 8); h.image_size = r.u(48, 8);
    h.segment_table_offset = r.u(56, 8); h.file_size = r.u(72, 8);
    h.map_align = r.u(96, 8); h.arch_flags = static_cast<std::uint32_t>(r.u(104, 4));
    if ((h.flags & ~pie) || (h.features & ~15ull) || h.arch_flags)
        fail("E_UNSUPPORTED", "unknown EPF flags, required features or architecture flags");
    if (h.features & feature_tls) fail("E_UNSUPPORTED", "TLS requires a target ABI extension");
    require(h.file_size == bytes.size(), "declared EPF file size differs from actual size");
    require(power2(h.map_align) && h.map_align >= 4096 && h.map_align <= max_file,
            "invalid x86-64 mapping alignment");
    require(h.image_size && h.image_size <= max_image && h.image_size % h.map_align == 0,
            "invalid image size or resource limit exceeded");
    require(h.type != FileType::shared || (h.flags == 0 && h.image_base == 0 && h.entry_rva == no_entry),
            "SHARED must have no PIE flag, no image_base and EPF_NO_ENTRY");
    require(!(h.flags & pie) || h.image_base == 0, "PIE image_base must be zero");
    const auto count = r.u(80, 4);
    require(count && count <= max_segments, "invalid segment count or resource limit exceeded");
    require(h.segment_table_offset >= 128 && h.segment_table_offset % 8 == 0, "invalid segment table offset");
    r.range(h.segment_table_offset, mul(count, 64));
    std::optional<std::size_t> dynamic_index;
    bool interp_seen = false, relro_seen = false;
    std::vector<Span> files, pages;
    std::uint64_t max_end = 0;
    for (std::uint64_t i = 0; i < count; ++i) {
        const auto at = h.segment_table_offset + i * 64;
        Segment s;
        const auto stype = r.u(at, 4);
        s.type = static_cast<SegmentType>(stype); s.flags = static_cast<std::uint32_t>(r.u(at + 4, 4));
        s.file_offset = r.u(at + 8, 8); s.rva = r.u(at + 16, 8);
        s.file_size = r.u(at + 24, 8); s.mem_size = r.u(at + 32, 8); s.align = r.u(at + 40, 8);
        r.zero(at + 48, 16);
        if (s.type == SegmentType::null) { r.zero(at + 4, 60); image.segments.push_back(s); continue; }
        require((s.flags & ~(required | 7u)) == 0, "unknown segment flags");
        r.range(s.file_offset, s.file_size);
        if (stype > 6) {
            if (s.flags & required) fail("E_UNSUPPORTED", "unknown required segment type " + hex(stype));
            require((s.flags & 7) == 0, "non-LOAD permission flags must be zero");
            image.segments.push_back(s); continue;
        }
        if (s.type != SegmentType::note) require((s.flags & required) != 0, "semantic segment must be REQUIRED");
        if (s.type == SegmentType::load) {
            require((s.flags & readable) && (s.flags & (writable | executable)) != (writable | executable),
                    "LOAD must be readable and must not be writable+executable");
            require(s.mem_size > 0 && s.file_size <= s.mem_size, "invalid LOAD sizes");
            require(power2(s.align) && s.align >= h.map_align &&
                    s.file_offset % s.align == 0 && s.rva % s.align == 0, "invalid LOAD alignment");
            require(h.image_base % s.align == 0, "fixed base does not satisfy LOAD alignment");
            require(contains(0, h.image_size, s.rva, s.mem_size), "LOAD outside image range");
            const auto page_end = up(add(s.rva, s.mem_size), h.map_align);
            if (!pages.empty()) require(s.rva >= add(pages.back().at, pages.back().size), "LOAD pages overlap or are not sorted by RVA");
            pages.push_back({s.rva, page_end - s.rva});
            if (s.file_size) files.push_back({s.file_offset, s.file_size});
            max_end = std::max(max_end, add(s.rva, s.mem_size));
            if (h.type == FileType::exec && !(h.flags & pie)) add(h.image_base, add(s.rva, s.mem_size));
        } else {
            require((s.flags & 7) == 0, "non-LOAD permission flags must be zero");
            require(power2(s.align), "invalid auxiliary segment alignment");
            if (s.type == SegmentType::dynamic) {
                require(!dynamic_index && s.file_size && s.file_size % 16 == 0 &&
                        s.file_size / 16 <= max_entries && s.file_offset % 8 == 0 && s.rva % 8 == 0,
                        "invalid or duplicate DYNAMIC segment");
                dynamic_index = image.segments.size();
            } else if (s.type == SegmentType::interp) {
                require(!interp_seen && h.type == FileType::exec && s.file_size > 1, "invalid or duplicate INTERP segment");
                auto path = r.string(s.file_offset, s.file_size, 0);
                require(path.size() + 1 == s.file_size && path.front() == '/', "INTERP must be a single absolute NUL-terminated path");
                image.interpreter = path; interp_seen = true;
            } else if (s.type == SegmentType::tls) {
                fail("E_UNSUPPORTED", "TLS segment requires a target TLS ABI");
            } else if (s.type == SegmentType::relro) {
                require(s.file_offset == 0 && s.file_size == 0 && s.mem_size &&
                        s.rva % h.map_align == 0 && s.mem_size % h.map_align == 0 &&
                        contains(0, h.image_size, s.rva, s.mem_size), "RELRO must describe full mapped pages");
                relro_seen = true;
            }
        }
        image.segments.push_back(s);
    }
    require(!pages.empty() && h.image_size == up(max_end, h.map_align), "image_size must match LOAD extent");
    std::sort(files.begin(), files.end(), [](const auto& a, const auto& b) { return a.at < b.at; });
    for (std::size_t i = 1; i < files.size(); ++i)
        require(!overlaps(files[i - 1].at, files[i - 1].size, files[i].at, files[i].size), "LOAD file ranges overlap");
    if (h.type == FileType::exec) require(h.entry_rva != no_entry && code_at(image, h.entry_rva), "entry is not in executable initialized LOAD content");
    for (const auto& s : image.segments) if (s.type == SegmentType::relro) {
        auto at = s.rva; const auto end = add(at, s.mem_size);
        while (at < end) {
            const Segment* load = nullptr;
            for (const auto& candidate : image.segments)
                if (candidate.type == SegmentType::load && contains(candidate.rva, up(candidate.mem_size, h.map_align), at, 1)) {
                    load = &candidate; break;
                }
            require(load && !(load->flags & executable), "RELRO covers an unmapped or executable page");
            at = std::min(end, up(add(load->rva, load->mem_size), h.map_align));
        }
    }
    require(!relro_seen || (h.features & feature_relro), "RELRO capability is not declared");
    std::vector<Span> protected_tables;
    auto protect = [&](std::uint64_t at, std::uint64_t size) {
        if (!size) return;
        for (const auto& old : protected_tables)
            require(!overlaps(at, size, old.at, old.size), "runtime metadata tables overlap");
        protected_tables.push_back({at, size});
    };
    if (dynamic_index) {
        const auto& d = image.segments[*dynamic_index];
        require(file_at(image, d.rva, d.file_size) == d.file_offset, "DYNAMIC file offset/RVA mismatch");
        protect(d.rva, d.file_size);
        std::map<std::uint32_t, std::uint64_t> tags;
        std::vector<std::uint64_t> names;
        bool ended = false;
        for (std::uint64_t offset = 0; offset < d.file_size; offset += 16) {
            const auto at = d.file_offset + offset;
            const auto tag = static_cast<std::uint32_t>(r.u(at, 4));
            const auto flags = r.u(at + 4, 4), value = r.u(at + 8, 8);
            if (ended) { r.zero(at, 16); continue; }
            if (!tag) { r.zero(at, 16); ended = true; continue; }
            require((flags & ~1ull) == 0, "unknown dynamic entry flags");
            if (tag > 14) {
                if (flags & 1) fail("E_UNSUPPORTED", "unknown required dynamic tag " + std::to_string(tag));
                continue;
            }
            if (tag == 9) names.push_back(value);
            else require(tags.emplace(tag, value).second, "duplicate singleton dynamic tag");
        }
        require(ended, "DYNAMIC has no NULL terminator");
        auto has = [&](std::uint32_t tag) { return tags.count(tag) != 0; };
        auto get = [&](std::uint32_t tag) { return has(tag) ? tags.at(tag) : 0; };
        auto group = [&](std::initializer_list<std::uint32_t> members) {
            std::size_t present = 0;
            for (auto tag : members) present += has(tag) ? 1 : 0;
            require(present == 0 || present == members.size(), "incomplete dynamic table descriptor");
            return present != 0;
        };
        auto table = [&](std::uint64_t at, std::uint64_t size) {
            require(at % 8 == 0, "runtime metadata table is not 8-byte aligned");
            auto offset = file_at(image, at, size); protect(at, size); return offset;
        };
        std::uint64_t strings = 0, string_size = 0;
        if (group({1, 2})) {
            string_size = get(2);
            require(string_size && string_size <= UINT32_MAX, "invalid dynamic string table size");
            strings = table(get(1), string_size);
            require(r.u(strings, 1) == 0, "dynamic strings must start with NUL");
        }
        std::uint64_t name_bytes = 0;
        auto string = [&](std::uint64_t index) {
            require(string_size != 0, "name used without dynamic string table");
            auto result = r.string(strings, string_size, index);
            name_bytes = add(name_bytes, result.size());
            if (name_bytes > max_total_names) fail("E_RESOURCE", "dynamic names exceed 64 MiB resource limit");
            return result;
        };
        for (auto index : names) { auto name = string(index); library_name(name); image.needed.push_back(std::move(name)); }
        if (has(10)) { image.soname = string(get(10)); library_name(*image.soname); }
        if (group({3, 4, 5})) {
            const auto n = get(4);
            require(n && n <= max_entries && get(5) == 32, "invalid dynamic symbol table size/entry length");
            const auto start = table(get(3), mul(n, 32));
            r.zero(start, 32);
            std::set<std::string> strong_exports;
            for (std::uint64_t i = 0; i < n; ++i) {
                const auto at = start + i * 32;
                Symbol s;
                s.name_offset = static_cast<std::uint32_t>(r.u(at, 4));
                require(r.u(at + 4, 4) == 0, "runtime symbol section_index must be zero");
                s.value = r.u(at + 8, 8); s.size = r.u(at + 16, 8);
                s.binding = static_cast<std::uint8_t>(r.u(at + 24, 1));
                s.type = static_cast<std::uint8_t>(r.u(at + 25, 1));
                s.visibility = static_cast<std::uint8_t>(r.u(at + 26, 1));
                auto domain = r.u(at + 27, 1); r.zero(at + 28, 4);
                require(s.binding <= 2 && s.type <= 4 && s.visibility <= 1, "unknown symbol attributes");
                if (domain == 4 || s.type == 4) fail("E_UNSUPPORTED", "TLS symbol requires a TLS ABI");
                require(domain == 0 || domain == 2 || domain == 3, "invalid runtime symbol definition domain");
                s.domain = static_cast<Domain>(domain); s.name = string(s.name_offset);
                if (s.domain == Domain::undef) {
                    require(s.value == 0, "undefined symbol must have value zero");
                    require(!i || (!s.name.empty() && s.binding && !s.visibility), "invalid undefined external symbol");
                } else if (s.domain == Domain::image) {
                    require(s.value <= h.image_size && (memory_load(image, s.value, s.size) ||
                        (s.size == 0 && std::any_of(image.segments.begin(), image.segments.end(), [&](const auto& seg) {
                            return seg.type == SegmentType::load && s.value == add(seg.rva, seg.mem_size);
                        }))), "image symbol outside LOAD memory: " + s.name);
                    if (s.type == 2) require(code_at(image, s.value), "function symbol is not executable file-backed content: " + s.name);
                }
                if (i && s.binding && !s.visibility) {
                    require(!s.name.empty(), "exported/imported symbol needs a name");
                    if (s.binding == 1 && s.domain != Domain::undef)
                        require(strong_exports.insert(s.name).second, "duplicate strong dynamic definition: " + s.name);
                }
                image.symbols.push_back(std::move(s));
            }
        }
        if (group({6, 7, 8})) {
            const auto n = get(7);
            require(n <= max_entries && get(8) == 32, "invalid relocation count/entry length");
            const auto start = table(get(6), mul(n, 32));
            for (std::uint64_t i = 0; i < n; ++i) {
                const auto at = start + i * 32;
                Relocation rel;
                rel.offset = r.u(at, 8); rel.addend = r.i64(at + 8);
                rel.symbol_index = static_cast<std::uint32_t>(r.u(at + 16, 4));
                auto relocation_type = r.u(at + 20, 4); r.zero(at + 24, 8);
                if (relocation_type > 5) fail("E_UNSUPPORTED", "unknown EPF relocation type " + std::to_string(relocation_type));
                rel.type = static_cast<RelocType>(relocation_type);
                require((rel.symbol_index == 0 && image.symbols.empty()) || rel.symbol_index < image.symbols.size(),
                        "relocation symbol index out of bounds");
                if (rel.type == RelocType::relative32 || rel.type == RelocType::relative64)
                    require(rel.symbol_index == 0, "RELATIVE relocation symbol_index must be zero");
                image.relocations.push_back(rel);
            }
        }
        auto array = [&](std::uint32_t address, std::uint32_t size, std::vector<std::uint64_t>& values) {
            if (!group({address, size})) return;
            const auto n = get(size); require(n <= max_entries, "function array exceeds resource limit");
            const auto at = table(get(address), mul(n, 8));
            for (std::uint64_t i = 0; i < n; ++i) {
                auto value = r.u(at + i * 8, 8);
                require(code_at(image, value), "function array entry is not executable initialized content");
                values.push_back(value);
            }
        };
        array(11, 12, image.init); array(13, 14, image.fini);
    }
    std::vector<Span> writes;
    bool nonrelative = false, external_reference = false;
    for (const auto& rel : image.relocations) {
        const auto width = relocation_width(rel.type);
        if (!width) continue;
        const auto* load = memory_load(image, rel.offset, width);
        require(load && !(load->flags & executable) && ((load->flags & writable) || is_relro(image, rel.offset, width)),
                "runtime relocation target is not writable/RELRO data at RVA " + hex(rel.offset));
        for (const auto& span : protected_tables)
            require(!overlaps(rel.offset, width, span.at, span.size), "runtime relocation overwrites metadata");
        writes.push_back({rel.offset, width});
        if (rel.type != RelocType::relative32 && rel.type != RelocType::relative64) nonrelative = true;
        if (rel.symbol_index && image.symbols[rel.symbol_index].domain == Domain::undef) external_reference = true;
        if (h.type == FileType::exec && !(h.flags & pie) &&
            (rel.type == RelocType::relative32 || rel.type == RelocType::relative64)) {
            const auto value = add_signed(h.image_base, rel.addend);
            require(rel.type != RelocType::relative32 || value <= UINT32_MAX, "RELATIVE32 value overflows");
        }
    }
    std::sort(writes.begin(), writes.end(), [](const auto& a, const auto& b) { return a.at < b.at; });
    for (std::size_t i = 1; i < writes.size(); ++i)
        require(!overlaps(writes[i - 1].at, writes[i - 1].size, writes[i].at, writes[i].size), "runtime relocation writes overlap");
    require(writes.empty() || (h.features & feature_runtime_reloc), "runtime relocation capability is not declared");
    require((image.needed.empty() && !external_reference && !image.interpreter) || (h.features & feature_dynamic_link),
            "dynamic linking capability is not declared");
    if (h.type == FileType::exec && !image.interpreter)
        require(!nonrelative && image.needed.empty(), "EXEC without INTERP can only use base-relative relocations");
    image.bytes = bytes;
    return image;
}

std::string inspect(const Image& image) {
    const auto& h = image.header;
    std::ostringstream out;
    out << "EPF 1.0, x86-64, little-endian, " << (h.type == FileType::shared ? "SHARED" : "EXEC")
        << ((h.flags & pie) ? " (PIE)" : "") << '\n'
        << "OS ABI: " << h.os_abi << "  ABI version: " << h.abi_version << '\n'
        << "Image base: " << hex(h.image_base) << "  Entry RVA: "
        << (h.entry_rva == no_entry ? "none" : hex(h.entry_rva)) << '\n'
        << "Image size: " << hex(h.image_size) << "  Map alignment: " << hex(h.map_align)
        << "  File size: " << h.file_size << '\n'
        << "Required features: " << hex(h.features);
    if (h.features & feature_runtime_reloc) out << " RUNTIME_RELOC";
    if (h.features & feature_dynamic_link) out << " DYNAMIC_LINK";
    if (h.features & feature_relro) out << " RELRO";
    out << "\nSegments: " << image.segments.size() << '\n';
    for (const auto& s : image.segments) {
        out << "  " << segment_name(s.type) << " rva=" << hex(s.rva) << " file=" << hex(s.file_offset)
            << " filesz=" << hex(s.file_size) << " memsz=" << hex(s.mem_size) << " align=" << hex(s.align);
        if (s.type == SegmentType::load)
            out << ' ' << ((s.flags & readable) ? 'R' : '-') << ((s.flags & writable) ? 'W' : '-') << ((s.flags & executable) ? 'X' : '-');
        if (s.flags & required) out << " REQUIRED";
        out << '\n';
    }
    if (image.interpreter) out << "Interpreter: " << quoted(*image.interpreter) << '\n';
    if (image.soname) out << "SONAME: " << quoted(*image.soname) << '\n';
    for (const auto& name : image.needed) out << "NEEDED: " << quoted(name) << '\n';
    out << "Dynamic symbols: " << image.symbols.size() << '\n';
    for (std::size_t i = 1; i < image.symbols.size(); ++i) {
        const auto& s = image.symbols[i];
        out << "  [" << i << "] " << quoted(s.name) << " domain=" << unsigned(s.domain)
            << " value=" << hex(s.value) << " size=" << s.size << " binding=" << unsigned(s.binding)
            << " visibility=" << unsigned(s.visibility) << '\n';
    }
    out << "Runtime relocations: " << image.relocations.size() << '\n';
    for (const auto& rel : image.relocations)
        out << "  rva=" << hex(rel.offset) << " type=" << static_cast<std::uint32_t>(rel.type)
            << " symbol=" << rel.symbol_index << " addend=" << rel.addend << '\n';
    out << "INIT functions: " << image.init.size() << "  FINI functions: " << image.fini.size() << '\n';
    return out.str();
}

std::size_t verify_dependencies(const std::filesystem::path& root,
                               const std::vector<std::filesystem::path>& library_paths) {
    struct Module { std::filesystem::path path; Image image; std::vector<std::size_t> dependencies; };
    std::vector<Module> modules;
    std::uint64_t total_bytes = 0;
    auto load = [&](const std::filesystem::path& path) {
        auto canonical = std::filesystem::canonical(path);
        for (std::size_t i = 0; i < modules.size(); ++i)
            if (std::filesystem::equivalent(canonical, modules[i].path)) return i;
        require(modules.size() < max_modules, "dependency graph exceeds 256-module resource limit");
        auto bytes = read_file(canonical);
        total_bytes = add(total_bytes, bytes.size());
        require(total_bytes <= max_file, "dependency graph exceeds total 256 MiB file limit");
        auto image = decode(bytes);
        if (!modules.empty()) {
            const auto& a = modules.front().image.header; const auto& b = image.header;
            require(b.type == FileType::shared, "dependency must be SHARED: " + canonical.u8string());
            if (a.os_abi != b.os_abi || a.abi_version != b.abi_version || a.map_align != b.map_align)
                fail("E_ABI", "dependency ABI/mapping profile mismatch: " + canonical.u8string());
        }
        modules.push_back({canonical, std::move(image), {}});
        return modules.size() - 1;
    };
    load(root);
    for (std::size_t i = 0; i < modules.size(); ++i) {
        const auto names = modules[i].image.needed;
        const auto parent = modules[i].path.parent_path();
        std::vector<std::size_t> dependencies;
        for (const auto& name : names) {
            std::vector<std::filesystem::path> paths{parent};
            paths.insert(paths.end(), library_paths.begin(), library_paths.end());
            std::optional<std::filesystem::path> candidate;
            for (const auto& directory : paths) {
                auto path = directory / std::filesystem::u8path(name);
                if (std::filesystem::is_regular_file(path)) { candidate = path; break; }
            }
            if (!candidate) fail("E_DEPENDENCY", "cannot find " + name + " needed by " + modules[i].path.u8string());
            dependencies.push_back(load(*candidate));
        }
        modules[i].dependencies = std::move(dependencies);
    }
    std::vector<unsigned> state(modules.size(), 0);
    std::function<void(std::size_t)> visit = [&](std::size_t index) {
        if (state[index] == 1) fail("E_DEPENDENCY", "dependency cycle through " + modules[index].path.u8string());
        if (state[index] == 2) return;
        state[index] = 1;
        for (auto dependency : modules[index].dependencies) visit(dependency);
        state[index] = 2;
    };
    visit(0);
    std::vector<std::unordered_map<std::string_view, bool>> exports(modules.size());
    for (std::size_t i = 0; i < modules.size(); ++i)
        for (const auto& symbol : modules[i].image.symbols)
            if (symbol.domain != Domain::undef && !symbol.visibility && symbol.binding)
                exports[i][symbol.name] = exports[i][symbol.name] || symbol.binding == 1;
    for (std::size_t index = 0; index < modules.size(); ++index) {
        std::deque<std::size_t> queue;
        std::vector<bool> seen(modules.size(), false); seen[index] = true;
        for (auto dep : modules[index].dependencies) queue.push_back(dep);
        std::vector<std::size_t> closure;
        while (!queue.empty()) {
            const auto current = queue.front(); queue.pop_front();
            if (seen[current]) continue;
            seen[current] = true; closure.push_back(current);
            for (auto dep : modules[current].dependencies) queue.push_back(dep);
        }
        std::set<std::uint32_t> references;
        for (const auto& rel : modules[index].image.relocations)
            if (rel.type != RelocType::none && rel.symbol_index) references.insert(rel.symbol_index);
        for (auto symbol_index : references) {
            const auto& symbol = modules[index].image.symbols[symbol_index];
            if (symbol.domain != Domain::undef) continue; // Defined symbols always bind locally.
            bool strong = false, weak = false;
            for (auto dependency : closure) {
                auto found = exports[dependency].find(symbol.name);
                if (found != exports[dependency].end()) {
                    if (found->second) strong = true;
                    else weak = true;
                }
                if (strong) break;
            }
            if (!strong && !weak && symbol.binding != 2)
                fail("E_SYMBOL", "unresolved strong symbol " + quoted(symbol.name) + " in " + modules[index].path.u8string());
        }
    }
    return modules.size();
}
} // namespace epf
