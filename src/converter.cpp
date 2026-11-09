#include "internal.hpp"
#include <set>

namespace epf {
using namespace detail;
namespace {
struct Region { Segment segment; Bytes data; };
struct Dynamic { std::uint32_t tag; std::uint64_t value; };

std::string relocation_name(std::uint32_t type) {
    switch (type) {
    case 1: return "R_X86_64_64";
    case 2: return "R_X86_64_PC32";
    case 5: return "R_X86_64_COPY";
    case 6: return "R_X86_64_GLOB_DAT";
    case 7: return "R_X86_64_JUMP_SLOT";
    case 8: return "R_X86_64_RELATIVE";
    case 10: return "R_X86_64_32";
    case 11: return "R_X86_64_32S";
    case 37: return "R_X86_64_IRELATIVE";
    default: return "ELF relocation " + std::to_string(type);
    }
}

std::vector<std::uint64_t> function_array(const ElfFile& elf, std::uint64_t origin,
                                         std::uint64_t array_tag, std::uint64_t size_tag,
                                         std::uint64_t single_tag) {
    std::vector<std::uint64_t> result;
    auto function = [&](std::uint64_t va) {
        require(va >= origin && elf.code_at(va), "initializer/finalizer is not a module-local file-backed function at " + hex(va));
        result.push_back(va - origin);
    };
    const auto single = elf.tags.find(single_tag);
    // Both arrays prepend their legacy single function: FINI is called in reverse.
    if (single != elf.tags.end() && single->second) function(single->second);
    auto array = elf.tags.find(array_tag);
    if (array == elf.tags.end()) return result;
    Reader r(*elf.bytes);
    const auto size = elf.tags.at(size_tag);
    if (!size) return result;
    auto file = elf.file_at(array->second, size);
    std::map<std::uint64_t, const ElfRelocation*> relocations;
    for (const auto& rel : elf.relocations) if (rel.type) {
        require(relocations.emplace(rel.offset, &rel).second, "multiple ELF relocations at the same location");
    }
    for (std::uint64_t offset = 0; offset < size; offset += 8) {
        auto value = r.u(file + offset, 8);
        auto found = relocations.find(add(array->second, offset));
        if (found != relocations.end()) {
            const auto& rel = *found->second;
            if (rel.type == 8 || rel.type == 38) {
                require(rel.symbol == 0, "relative initializer relocation must use symbol zero");
                value = add_signed(0, rel.addend);
            } else if (rel.type == 1 || rel.type == 6 || rel.type == 7) {
                require(rel.symbol < elf.symbols.size() && elf.symbols[rel.symbol].section != 0,
                        "external initializer/finalizer cannot be represented as an EPF RVA");
                const auto& symbol = elf.symbols[rel.symbol];
                require(symbol.section != 0xfff1 || elf.type == 2,
                        "absolute initializer in a movable image is not representable as an RVA");
                value = add_signed(symbol.value, rel.type == 1 ? rel.addend : 0);
            } else {
                fail("E_UNSUPPORTED", "initializer uses " + relocation_name(rel.type));
            }
        }
        function(value);
    }
    return result;
}
} // namespace

Image convert(const Bytes& bytes, const ConvertOptions& options) {
    if (!options.profile.os_abi)
        fail("E_ARGUMENT", "supply an explicit OS ABI using --profile or --os-abi");
    const auto map_align = options.profile.map_align;
    if (!power2(map_align) || map_align < 4096 || map_align > max_file)
        fail("E_ARGUMENT", "x86-64 map_align must be a power of two from 4096 to 256 MiB");
    const auto elf = read_elf(bytes);
    if (options.type == FileType::shared && (elf.type != 3 || elf.marked_pie || elf.interpreter))
        fail("E_TARGET", "shared output requires an ET_DYN shared library, not an executable");
    if (elf.type == 2 && elf.marked_pie) fail("E_FORMAT", "ET_EXEC cannot declare DF_1_PIE");
    if (options.type == FileType::exec && !elf.code_at(elf.entry))
        fail("E_TARGET", "ELF entry must be in the initialized bytes of an executable LOAD");
    if (options.type == FileType::exec && options.soname)
        fail("E_ARGUMENT", "--soname is only valid for shared output");

    std::uint64_t base_align = map_align;
    for (const auto& s : elf.loads) base_align = std::max(base_align, s.align);
    require(power2(base_align) && base_align <= max_file, "ELF base alignment exceeds resource limit");
    const auto origin = down(elf.loads.front().vaddr, base_align);
    Header header;
    header.type = options.type;
    header.os_abi = *options.profile.os_abi;
    header.abi_version = options.profile.abi_version;
    header.map_align = map_align;
    header.flags = options.type == FileType::exec && elf.type == 3 ? pie : 0;
    header.image_base = options.type == FileType::exec && elf.type == 2 ? origin : 0;
    header.entry_rva = options.type == FileType::exec ? elf.entry - origin : no_entry;

    std::vector<Region> regions;
    std::uint64_t image_end = 0;
    bool base_alignment_encoded = false;
    for (const auto& s : elf.loads) {
        Region region;
        const auto start = down(s.vaddr, map_align), prefix = s.vaddr - start;
        auto& out = region.segment;
        out.type = SegmentType::load;
        out.flags = required | readable | ((s.flags & 2) ? writable : 0) | ((s.flags & 1) ? executable : 0);
        out.rva = start - origin;
        out.align = map_align;
        // One aligned LOAD is sufficient to retain all original base-alignment constraints.
        if (!base_alignment_encoded && out.rva % base_align == 0) {
            out.align = base_align;
            base_alignment_encoded = true;
        }
        out.mem_size = add(prefix, s.memsz);
        out.file_size = s.filesz ? add(prefix, s.filesz) : 0;
        if (!regions.empty() && out.rva < up(image_end, map_align))
            fail("E_LAYOUT", "ELF LOAD pages overlap at " + hex(start) + "; relink with separate page-aligned segments");
        image_end = add(out.rva, out.mem_size);
        require(image_end <= max_image && out.file_size <= max_file, "ELF image exceeds resource limit");
        region.data.resize(static_cast<std::size_t>(out.file_size), 0);
        if (s.filesz)
            std::copy_n(bytes.begin() + static_cast<std::ptrdiff_t>(s.offset), static_cast<std::size_t>(s.filesz),
                        region.data.begin() + static_cast<std::ptrdiff_t>(prefix));
        regions.push_back(std::move(region));
    }
    std::vector<Segment> relro_segments;
    for (const auto& s : elf.relro_segments) {
        if (!s.memsz) continue;
        const auto start = down(s.vaddr, map_align), end = up(add(s.vaddr, s.memsz), map_align);
        require(start >= origin, "RELRO precedes image origin");
        for (const auto& load : elf.loads) {
            if (overlaps(start, s.vaddr - start, load.vaddr, load.memsz) ||
                overlaps(add(s.vaddr, s.memsz), end - add(s.vaddr, s.memsz), load.vaddr, load.memsz))
                fail("E_LAYOUT", "RELRO rounding would protect additional program data; relink on full page boundaries");
        }
        Segment relro_segment;
        relro_segment.type = SegmentType::relro; relro_segment.flags = required;
        relro_segment.rva = start - origin; relro_segment.mem_size = end - start;
        relro_segment.align = map_align;
        relro_segments.push_back(relro_segment);
    }
    if (!relro_segments.empty()) header.features |= feature_relro;

    std::vector<Symbol> symbols;
    bool cross_module = !elf.needed.empty() || elf.interpreter;
    for (std::size_t i = 0; i < elf.symbols.size(); ++i) {
        const auto& s = elf.symbols[i];
        Symbol out;
        out.name = s.name; out.size = s.size; out.binding = s.binding; out.type = s.type;
        // PROTECTED is representable because EPF always binds local definitions locally.
        out.visibility = s.visibility == 1 || s.visibility == 2 ? 1 : 0;
        if (s.section == 0) {
            out.domain = Domain::undef;
        } else if (s.section == 0xfff1) {
            out.domain = Domain::absolute; out.value = s.value;
        } else {
            require(s.value >= origin, "defined dynamic symbol precedes the image: " + s.name);
            out.domain = Domain::image; out.value = s.value - origin;
        }
        if (i && out.binding && !out.visibility && !out.name.empty()) cross_module = true;
        symbols.push_back(std::move(out));
    }
    std::vector<Relocation> relocations;
    bool nonrelative = false;
    for (const auto& r : elf.relocations) {
        if (!r.type) continue;
        require(r.offset >= origin, "relocation precedes the image");
        Relocation out;
        out.offset = r.offset - origin; out.addend = r.addend; out.symbol_index = r.symbol;
        switch (r.type) {
        case 1: out.type = RelocType::abs64; break;
        case 2: out.type = RelocType::pcrel32; break;
        case 6: case 7: out.type = RelocType::abs64; out.addend = 0; break;
        case 8: case 38:
            require(r.symbol == 0, "ELF relative relocation must use symbol zero");
            out.type = RelocType::relative64;
            out.addend = subtract_origin(r.addend, origin);
            break;
        case 10: out.type = RelocType::abs32; break;
        default:
            fail("E_UNSUPPORTED", relocation_name(r.type) + " at ELF VA " + hex(r.offset) +
                 " cannot be converted to EPF v1; relink without this runtime relocation");
        }
        if (out.type != RelocType::relative64) nonrelative = true;
        relocations.push_back(out);
    }
    if (!relocations.empty()) header.features |= feature_runtime_reloc;
    if (cross_module) header.features |= feature_dynamic_link;
    const auto init = function_array(elf, origin, 25, 27, 12);
    const auto fini = function_array(elf, origin, 26, 28, 13);
    const bool needs_interpreter = options.type == FileType::exec && (cross_module || nonrelative);
    if (needs_interpreter && options.profile.interpreter.empty())
        fail("E_ABI", "this executable needs an EPF interpreter; set interpreter in the target profile or --interpreter");
    if (needs_interpreter) header.features |= feature_dynamic_link;
    if (needs_interpreter && (options.profile.interpreter.front() != '/' ||
                              options.profile.interpreter.find('\0') != std::string::npos))
        fail("E_ARGUMENT", "the target interpreter must be an absolute NUL-free path");

    std::vector<std::string> needed;
    for (const auto& name : elf.needed) {
        const auto found = options.needed_map.find(name);
        needed.push_back(found == options.needed_map.end() ? name : found->second);
        library_name(needed.back());
    }
    auto soname = options.soname ? options.soname : elf.soname;
    if (soname) library_name(*soname);
    const bool has_dynamic = !symbols.empty() || !relocations.empty() || !needed.empty() || soname || !init.empty() || !fini.empty();
    Bytes metadata;
    std::uint64_t meta_rva = 0, directory_offset = 0, directory_size = 0;
    if (has_dynamic || !base_alignment_encoded) {
        Region meta;
        meta.segment.type = SegmentType::load; meta.segment.flags = required | readable;
        meta.segment.align = base_alignment_encoded ? map_align : base_align;
        meta.segment.rva = up(image_end, meta.segment.align);
        meta_rva = meta.segment.rva;
        if (has_dynamic) {
            if (symbols.empty()) symbols.emplace_back();
            Bytes strings(1, 0);
            std::map<std::string, std::uint32_t> indexes{{"", 0}};
            auto intern = [&](const std::string& text) {
                auto old = indexes.find(text);
                if (old != indexes.end()) return old->second;
                require(text.find('\0') == std::string::npos && strings.size() + text.size() + 1 <= max_file,
                        "dynamic string table exceeds resource limit");
                auto index = static_cast<std::uint32_t>(strings.size());
                strings.insert(strings.end(), text.begin(), text.end()); strings.push_back(0);
                indexes.emplace(text, index);
                return index;
            };
            for (auto& s : symbols) s.name_offset = intern(s.name);
            std::vector<std::uint32_t> needed_offsets;
            for (const auto& name : needed) needed_offsets.push_back(intern(name));
            std::optional<std::uint32_t> soname_offset;
            if (soname) soname_offset = intern(*soname);
            std::vector<Dynamic> tags;
            auto table = [&](std::uint32_t address_tag, std::uint32_t count_tag, std::uint64_t count,
                             std::uint64_t size, std::optional<std::pair<std::uint32_t, std::uint64_t>> entry = {}) {
                auto offset = reserve(metadata, size);
                tags.push_back({address_tag, add(meta_rva, offset)});
                tags.push_back({count_tag, count});
                if (entry) tags.push_back({entry->first, entry->second});
                return offset;
            };
            auto strings_at = table(1, 2, strings.size(), strings.size());
            std::copy(strings.begin(), strings.end(), metadata.begin() + static_cast<std::ptrdiff_t>(strings_at));
            auto syms_at = table(3, 4, symbols.size(), mul(symbols.size(), 32), {{5, 32}});
            for (std::size_t i = 0; i < symbols.size(); ++i) {
                const auto& s = symbols[i]; const auto at = syms_at + i * 32;
                put(metadata, at, s.name_offset, 4); put(metadata, at + 8, s.value, 8);
                put(metadata, at + 16, s.size, 8); put(metadata, at + 24, s.binding, 1);
                put(metadata, at + 25, s.type, 1); put(metadata, at + 26, s.visibility, 1);
                put(metadata, at + 27, static_cast<std::uint8_t>(s.domain), 1);
            }
            if (!relocations.empty()) {
                auto rels_at = table(6, 7, relocations.size(), mul(relocations.size(), 32), {{8, 32}});
                for (std::size_t i = 0; i < relocations.size(); ++i) {
                    const auto& rel = relocations[i]; auto at = rels_at + i * 32;
                    put(metadata, at, rel.offset, 8); put(metadata, at + 8, static_cast<std::uint64_t>(rel.addend), 8);
                    put(metadata, at + 16, rel.symbol_index, 4);
                    put(metadata, at + 20, static_cast<std::uint32_t>(rel.type), 4);
                }
            }
            for (auto offset : needed_offsets) tags.push_back({9, offset});
            if (soname_offset) tags.push_back({10, *soname_offset});
            auto array = [&](const auto& values, std::uint32_t address_tag, std::uint32_t count_tag) {
                if (values.empty()) return;
                auto at = table(address_tag, count_tag, values.size(), mul(values.size(), 8));
                for (std::size_t i = 0; i < values.size(); ++i) put(metadata, at + i * 8, values[i], 8);
            };
            array(init, 11, 12); array(fini, 13, 14);
            directory_size = mul(tags.size() + 1, 16);
            directory_offset = reserve(metadata, directory_size);
            for (std::size_t i = 0; i < tags.size(); ++i) {
                auto at = directory_offset + i * 16;
                put(metadata, at, tags[i].tag, 4); put(metadata, at + 4, 1, 4);
                put(metadata, at + 8, tags[i].value, 8);
            }
        } else metadata.resize(8, 0); // Alignment anchor, only for unusual nonzero ELF origins.
        meta.segment.file_size = meta.segment.mem_size = metadata.size();
        meta.data = std::move(metadata);
        image_end = add(meta.segment.rva, meta.segment.mem_size);
        regions.push_back(std::move(meta));
    }
    header.image_size = up(image_end, map_align);
    require(header.image_size <= max_image, "output image exceeds 16 GiB resource limit");
    if (header.image_base) add(header.image_base, header.image_size);
    const auto count = regions.size() + relro_segments.size() + (has_dynamic ? 1 : 0) + (needs_interpreter ? 1 : 0);
    require(count <= max_segments, "output has too many segments");
    Bytes output(static_cast<std::size_t>(add(128, mul(count, 64))), 0);
    std::vector<Segment> segments;
    for (auto& region : regions) {
        region.segment.file_offset = region.data.empty() ? 0 : append(output, region.data, region.segment.align);
        segments.push_back(region.segment);
    }
    if (has_dynamic) {
        Segment segment;
        segment.type = SegmentType::dynamic; segment.flags = required; segment.align = 8;
        segment.file_offset = add(segments.back().file_offset, directory_offset);
        segment.rva = add(meta_rva, directory_offset);
        segment.file_size = segment.mem_size = directory_size;
        segments.push_back(segment);
    }
    if (needs_interpreter) {
        const auto& path = options.profile.interpreter;
        Bytes path_bytes(path.begin(), path.end()); path_bytes.push_back(0);
        Segment segment;
        segment.type = SegmentType::interp; segment.flags = required; segment.align = 1;
        segment.file_offset = append(output, path_bytes);
        segment.file_size = segment.mem_size = path_bytes.size();
        segments.push_back(segment);
    }
    segments.insert(segments.end(), relro_segments.begin(), relro_segments.end());
    header.file_size = output.size();
    encode_header(output, header, segments.size());
    for (std::size_t i = 0; i < segments.size(); ++i) encode_segment(output, 128 + i * 64, segments[i]);
    // A separate reader checks all cross-references and permissions before any file is written.
    return decode(output);
}
} // namespace epf
