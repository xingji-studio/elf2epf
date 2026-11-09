#include "internal.hpp"
#include <set>

namespace epf::detail {
namespace {
constexpr std::uint64_t dt_gnu_hash = 0x6ffffef5, dt_flags1 = 0x6ffffffb;
constexpr std::uint64_t dt_symtabsz = 39;
struct Section {
    std::uint32_t type = 0, link = 0;
    std::uint64_t addr = 0, offset = 0, size = 0, entsize = 0;
};
void check_notes(const Reader& r, const ElfSegment& segment) {
    auto at = segment.offset;
    const auto end = add(at, segment.filesz);
    while (at < end) {
        // Linkers may leave zero padding after the final note.
        if (end - at < 12) { r.zero(at, end - at); break; }
        const auto name_size = r.u(at, 4), desc_size = r.u(at + 4, 4), type = r.u(at + 8, 4);
        const auto name = add(at, 12), desc = up(add(name, name_size), 4);
        const auto next = up(add(desc, desc_size), 4);
        require(next <= end && next > at, "ELF note extends beyond PT_NOTE");
        if (name_size == 4 && r.u(name, 4) == 0x00554e47 && type == 5) {
            auto property = desc;
            const auto desc_end = add(desc, desc_size);
            while (property < desc_end) {
                require(desc_end - property >= 8, "truncated GNU property");
                const auto prop_type = r.u(property, 4), size = r.u(property + 4, 4);
                require(size <= desc_end - property - 8, "GNU property out of bounds");
                if (prop_type == 0xc0008002) {
                    require(size == 4, "bad x86 ISA requirement property");
                    if (r.u(property + 8, 4) & ~1ull)
                        fail("E_UNSUPPORTED", "ELF requires an extended x86 ISA; arch_flags ABI is not defined");
                } else if (prop_type == 0xc0000002) {
                    require(size == 4, "bad x86 feature property");
                    if (r.u(property + 8, 4))
                        fail("E_UNSUPPORTED", "CET/IBT/SHSTK GNU properties need an EPF architecture ABI");
                } else if (prop_type != 0xc0010002 && prop_type != 0xc0010001 && prop_type != 2) {
                    fail("E_UNSUPPORTED", "unhandled GNU property " + hex(prop_type));
                }
                property = up(add(property + 8, size), 8);
                require(property <= desc_end, "GNU property padding out of bounds");
            }
        }
        at = next;
    }
}
} // namespace

std::uint64_t ElfFile::file_at(std::uint64_t va, std::uint64_t size) const {
    for (const auto& s : loads)
        if (contains(s.vaddr, s.filesz, va, size)) return add(s.offset, va - s.vaddr);
    fail("E_FORMAT", "ELF virtual range is not file-backed by PT_LOAD at " + hex(va));
}
bool ElfFile::code_at(std::uint64_t va) const {
    return std::any_of(loads.begin(), loads.end(), [va](const auto& s) {
        return (s.flags & 1) && contains(s.vaddr, s.filesz, va, 1);
    });
}

ElfFile read_elf(const Bytes& bytes) {
    Reader r(bytes);
    r.range(0, 64);
    require(r.u(0, 4) == 0x464c457f, "input is not ELF");
    if (r.u(4, 1) != 2 || r.u(5, 1) != 1 || r.u(18, 2) != 62)
        fail("E_UNSUPPORTED", "only little-endian ELF64 x86-64 (LP64) is supported");
    require(r.u(6, 1) == 1 && r.u(20, 4) == 1, "unsupported ELF version");
    require(r.u(52, 2) == 64, "ELF64 header size must be 64");
    if (r.u(48, 4)) fail("E_UNSUPPORTED", "unknown ELF architecture flags");
    ElfFile elf;
    elf.bytes = &bytes;
    elf.type = static_cast<std::uint16_t>(r.u(16, 2));
    if (elf.type != 2 && elf.type != 3)
        fail("E_UNSUPPORTED", "input must be a linked ET_EXEC or ET_DYN file; link ET_REL objects first");
    elf.entry = r.u(24, 8);
    const auto phoff = r.u(32, 8), shoff = r.u(40, 8);
    auto phnum = r.u(56, 2), shnum = r.u(60, 2);
    const auto phent = r.u(54, 2), shent = r.u(58, 2);
    require(phoff >= 64 && phent == 56, "invalid ELF64 program header table");
    if (shoff) {
        require(shoff >= 64 && shent == 64, "invalid ELF64 section header table");
        r.range(shoff, 64);
        if (!shnum) shnum = r.u(shoff + 32, 8);
        if (phnum == 0xffff) phnum = r.u(shoff + 44, 4);
    } else {
        require(shnum == 0 && r.u(62, 2) == 0 && phnum != 0xffff,
                "ELF extended indexes require a section table");
    }
    require(phnum && phnum <= max_segments, "ELF program header count exceeds resource limit");
    r.range(phoff, mul(phnum, phent));
    std::vector<Section> sections;
    if (shoff) {
        require(shnum && shnum <= max_entries, "ELF section count exceeds resource limit");
        r.range(shoff, mul(shnum, shent));
        for (std::uint64_t i = 0; i < shnum; ++i) {
            const auto at = add(shoff, mul(i, shent));
            Section s;
            s.type = static_cast<std::uint32_t>(r.u(at + 4, 4));
            s.addr = r.u(at + 16, 8); s.offset = r.u(at + 24, 8);
            s.size = r.u(at + 32, 8); s.link = static_cast<std::uint32_t>(r.u(at + 40, 4));
            s.entsize = r.u(at + 56, 8);
            if (s.type != 0 && s.type != 8) r.range(s.offset, s.size);
            sections.push_back(s);
        }
    }
    std::optional<ElfSegment> dynamic;
    std::vector<ElfSegment> notes;
    bool stack_seen = false;
    for (std::uint64_t i = 0; i < phnum; ++i) {
        const auto at = add(phoff, mul(i, phent));
        ElfSegment s;
        s.type = static_cast<std::uint32_t>(r.u(at, 4));
        s.flags = static_cast<std::uint32_t>(r.u(at + 4, 4));
        s.offset = r.u(at + 8, 8); s.vaddr = r.u(at + 16, 8);
        s.filesz = r.u(at + 32, 8); s.memsz = r.u(at + 40, 8); s.align = r.u(at + 48, 8);
        r.range(s.offset, s.filesz);
        switch (s.type) {
        case 0: break;
        case 1:
            require(s.filesz <= s.memsz, "ELF PT_LOAD file size exceeds memory size");
            require(s.align <= 1 || power2(s.align), "invalid PT_LOAD alignment");
            if (s.align > 1)
                require(s.vaddr % s.align == s.offset % s.align, "incongruent PT_LOAD alignment");
            require((s.flags & ~7u) == 0, "unknown PT_LOAD flags");
            if (!(s.flags & 4) || ((s.flags & 3) == 3))
                fail("E_LAYOUT", "EPF LOAD requires R and forbids W+X at " + hex(s.vaddr));
            add(s.vaddr, s.memsz);
            if (s.memsz) elf.loads.push_back(s);
            break;
        case 2:
            require(!dynamic, "multiple PT_DYNAMIC segments");
            dynamic = s; break;
        case 3:
            require(!elf.interpreter && s.filesz > 1, "invalid or duplicate PT_INTERP");
            require(r.string(s.offset, s.filesz, 0).size() + 1 == s.filesz,
                    "PT_INTERP must contain exactly one NUL-terminated path");
            elf.interpreter = true; break;
        case 4: notes.push_back(s); break;
        case 6: break; // Original in-memory headers remain ordinary LOAD payload.
        case 7: fail("E_UNSUPPORTED", "PT_TLS requires a target TLS ABI");
        case 0x6474e550: break; // GNU EH_FRAME discovery is not translated; see ABI contract.
        case 0x6474e551:
            require(!stack_seen, "duplicate PT_GNU_STACK");
            stack_seen = true;
            if (s.flags & 1) fail("E_UNSUPPORTED", "executable stack is not supported by EPF v1");
            break;
        case 0x6474e552: elf.relro_segments.push_back(s); break;
        case 0x6474e553: notes.push_back(s); break;
        default: fail("E_UNSUPPORTED", "unhandled ELF program header type " + hex(s.type));
        }
    }
    require(!elf.loads.empty(), "ELF has no nonempty PT_LOAD");
    std::sort(elf.loads.begin(), elf.loads.end(), [](const auto& a, const auto& b) {
        return a.vaddr < b.vaddr;
    });
    for (std::size_t i = 1; i < elf.loads.size(); ++i)
        require(add(elf.loads[i - 1].vaddr, elf.loads[i - 1].memsz) <= elf.loads[i].vaddr,
                "overlapping ELF PT_LOAD memory ranges");
    for (const auto& s : notes) check_notes(r, s);
    if (!dynamic) return elf;
    const auto& d = *dynamic;
    require(d.filesz && d.filesz % 16 == 0 && d.filesz / 16 <= max_entries,
            "invalid PT_DYNAMIC size");
    require(elf.file_at(d.vaddr, d.filesz) == d.offset, "PT_DYNAMIC file/address mismatch");
    bool terminated = false;
    std::vector<std::uint64_t> needed;
    const std::set<std::uint64_t> accepted = {
        2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 20, 21, 23, 24,
        25, 26, 27, 28, 30, 32, 33, dt_symtabsz, dt_gnu_hash, dt_flags1, 0x6ffffff9
    };
    for (std::uint64_t i = 0; i < d.filesz / 16; ++i) {
        const auto at = d.offset + i * 16, tag = r.u(at, 8), value = r.u(at + 8, 8);
        if (!tag) { terminated = true; break; }
        if (tag == 1) { needed.push_back(value); continue; }
        if (!accepted.count(tag)) {
            std::string hint;
            if (tag == 17 || tag == 18 || tag == 19 || tag == 35 || tag == 36 || tag == 37)
                hint = " (REL/RELR input is not implemented; link with RELA relocations)";
            if (tag == 22) hint = " (text relocations are forbidden)";
            if (tag == 15 || tag == 29) hint = " (use the target ABI library search paths instead of RPATH/RUNPATH)";
            if (tag == 0x6ffffff0 || (tag >= 0x6ffffffc && tag <= 0x6fffffff))
                hint = " (symbol versioning is not representable in base EPF v1)";
            fail("E_UNSUPPORTED", "unhandled ELF dynamic tag " + hex(tag) + hint);
        }
        require(elf.tags.emplace(tag, value).second, "duplicate ELF dynamic tag " + hex(tag));
    }
    require(terminated, "unterminated PT_DYNAMIC");
    auto has = [&](std::uint64_t t) { return elf.tags.count(t) != 0; };
    auto get = [&](std::uint64_t t) { return has(t) ? elf.tags.at(t) : 0; };
    if (get(30) & ~10ull) fail("E_UNSUPPORTED", "unsupported DT_FLAGS (TLS, text relocations or ORIGIN)");
    if (get(dt_flags1) & ~(0x08000000ull | 1ull)) fail("E_UNSUPPORTED", "unsupported DT_FLAGS_1");
    elf.marked_pie = (get(dt_flags1) & 0x08000000) != 0;
    if (get(32) || get(33)) fail("E_UNSUPPORTED", "PREINIT_ARRAY has no EPF v1 equivalent");
    require(has(5) == has(10), "incomplete ELF dynamic string table");
    std::uint64_t str = 0, strsz = get(10);
    if (has(5)) {
        require(strsz > 0 && strsz <= UINT32_MAX, "invalid dynamic string table size");
        str = elf.file_at(get(5), strsz);
        require(r.u(str, 1) == 0, "dynamic string table must begin with NUL");
    }
    std::uint64_t name_bytes = 0;
    auto dyn_string = [&](std::uint64_t index) {
        require(has(5), "dynamic name without a string table");
        auto result = r.string(str, strsz, index);
        name_bytes = add(name_bytes, result.size());
        if (name_bytes > max_total_names) fail("E_RESOURCE", "dynamic names exceed 64 MiB resource limit");
        return result;
    };
    for (auto index : needed) {
        auto name = dyn_string(index);
        library_name(name);
        elf.needed.push_back(std::move(name));
    }
    if (has(14)) { elf.soname = dyn_string(get(14)); library_name(*elf.soname); }
    require(has(6) == has(11), "incomplete ELF dynamic symbol table");
    if (has(6)) {
        require(has(5) && get(11) == 24, "invalid ELF64 dynamic symbol entry size");
        std::optional<std::uint64_t> count;
        auto use_count = [&](std::uint64_t n) {
            require(n && n <= max_entries, "dynamic symbol count exceeds resource limit");
            require(!count || *count == n, "inconsistent dynamic symbol counts");
            count = n;
        };
        if (has(dt_symtabsz)) {
            require(get(dt_symtabsz) % 24 == 0, "DT_SYMTABSZ is not a multiple of DT_SYMENT");
            use_count(get(dt_symtabsz) / 24);
        }
        for (const auto& s : sections) if (s.type == 11 && s.addr == get(6)) {
            require(s.entsize == 24 && s.size % 24 == 0 && s.link < sections.size(), "invalid SHT_DYNSYM");
            require(elf.file_at(s.addr, s.size) == s.offset, "SHT_DYNSYM address/file mismatch");
            const auto& strings = sections[s.link];
            require(strings.type == 3 && strings.addr == get(5) && strings.size == strsz && strings.offset == str,
                    "SHT_DYNSYM string table disagrees with PT_DYNAMIC");
            use_count(s.size / 24);
        }
        if (has(4)) {
            auto at = elf.file_at(get(4), 8);
            auto buckets = r.u(at, 4), chains = r.u(at + 4, 4);
            require(buckets && buckets <= max_entries, "invalid SysV hash bucket count");
            elf.file_at(get(4), add(8, mul(add(buckets, chains), 4)));
            use_count(chains);
        }
        if (has(dt_gnu_hash)) {
            const auto va = get(dt_gnu_hash), at = elf.file_at(va, 16);
            const auto buckets = r.u(at, 4), first = r.u(at + 4, 4), bloom = r.u(at + 8, 4);
            require(buckets && buckets <= max_entries && first <= max_entries &&
                    power2(bloom) && bloom <= max_entries && r.u(at + 12, 4) < 64,
                    "invalid GNU hash header");
            const auto bucket_va = add(va, add(16, mul(bloom, 8)));
            const auto bucket_at = elf.file_at(bucket_va, mul(buckets, 4));
            const auto chain_va = add(bucket_va, mul(buckets, 4));
            std::uint64_t n = first, steps = 0;
            for (std::uint64_t i = 0; i < buckets; ++i) {
                auto index = r.u(bucket_at + i * 4, 4);
                if (!index) continue;
                require(index >= first && index < max_entries, "invalid GNU hash bucket");
                for (;;) {
                    require(++steps <= max_entries && index < max_entries, "GNU hash chain exceeds resource limit");
                    const auto word = r.u(elf.file_at(add(chain_va, mul(index - first, 4)), 4), 4);
                    n = std::max(n, index + 1);
                    ++index;
                    if (word & 1) break;
                }
            }
            // An empty GNU hash does not delimit trailing undefined symbols.
            // Use an authoritative count from sections, DT_SYMTABSZ or DT_HASH.
            if (steps) use_count(n);
            else if (count) require(first <= *count, "GNU hash symbol offset exceeds symbol count");
        }
        require(count.has_value(), "cannot determine dynamic symbol count without size, hash or SHT_DYNSYM");
        const auto sym_at = elf.file_at(get(6), mul(*count, 24));
        r.zero(sym_at, 24);
        for (std::uint64_t i = 0; i < *count; ++i) {
            const auto at = sym_at + i * 24;
            ElfSymbol s;
            s.name = dyn_string(r.u(at, 4));
            auto info = r.u(at + 4, 1), other = r.u(at + 5, 1);
            s.binding = static_cast<std::uint8_t>(info >> 4);
            s.type = static_cast<std::uint8_t>(info & 15);
            s.visibility = static_cast<std::uint8_t>(other & 3);
            s.section = static_cast<std::uint16_t>(r.u(at + 6, 2));
            s.value = r.u(at + 8, 8); s.size = r.u(at + 16, 8);
            if (s.binding > 2 || s.type > 3 || (other & ~3ull))
                fail("E_UNSUPPORTED", "unsupported symbol binding/type/visibility for " + s.name + " (TLS/IFUNC/GNU_UNIQUE need extensions)");
            if (s.section >= 0xff00 && s.section != 0xfff1)
                fail("E_UNSUPPORTED", "unsupported symbol section index for " + s.name);
            require(!shoff || s.section == 0xfff1 || s.section < sections.size(), "symbol section index out of bounds");
            if (s.section == 0 && s.value)
                fail("E_UNSUPPORTED", "undefined symbol with a nonzero canonical PLT address: " + s.name);
            elf.symbols.push_back(std::move(s));
        }
    } else {
        require(!has(4) && !has(dt_gnu_hash) && !has(dt_symtabsz), "symbol metadata without DT_SYMTAB");
    }
    struct Table { std::uint64_t va, size; };
    std::vector<Table> relocation_tables;
    require(has(7) == has(8) && has(7) == has(9), "incomplete DT_RELA table");
    if (has(7)) {
        require(get(9) == 24, "DT_RELAENT must be 24");
        relocation_tables.push_back({get(7), get(8)});
    }
    require(has(23) == has(2) && has(23) == has(20), "incomplete DT_JMPREL table");
    if (has(23)) {
        if (get(20) != 7) fail("E_UNSUPPORTED", "DT_JMPREL must use RELA");
        relocation_tables.push_back({get(23), get(2)});
    }
    for (std::size_t i = 0; i < relocation_tables.size(); ++i) {
        const auto& table = relocation_tables[i];
        require(table.size % 24 == 0, "ELF relocation table size is not a multiple of 24");
        require(table.size / 24 <= max_entries - elf.relocations.size(), "too many runtime relocations");
        for (std::size_t j = 0; j < i; ++j)
            require(!overlaps(table.va, table.size, relocation_tables[j].va, relocation_tables[j].size),
                    "overlapping ELF dynamic relocation tables");
        if (!table.size) continue;
        const auto at = elf.file_at(table.va, table.size);
        for (std::uint64_t pos = 0; pos < table.size; pos += 24) {
            const auto info = r.u(at + pos + 8, 8);
            ElfRelocation rel;
            rel.offset = r.u(at + pos, 8); rel.addend = r.i64(at + pos + 16);
            rel.symbol = static_cast<std::uint32_t>(info >> 32);
            rel.type = static_cast<std::uint32_t>(info);
            require((rel.symbol == 0 && elf.symbols.empty()) || rel.symbol < elf.symbols.size(),
                    "ELF relocation symbol index out of bounds");
            elf.relocations.push_back(rel);
        }
    }
    if (has(0x6ffffff9)) {
        require(has(7) && get(0x6ffffff9) <= get(8) / 24, "invalid DT_RELACOUNT");
        for (std::uint64_t i = 0; i < get(0x6ffffff9); ++i)
            require(elf.relocations[static_cast<std::size_t>(i)].type == 8 &&
                    elf.relocations[static_cast<std::size_t>(i)].symbol == 0, "bad DT_RELACOUNT prefix");
    }
    for (auto pair : {std::pair<std::uint64_t, std::uint64_t>{25, 27}, {26, 28}, {32, 33}}) {
        require(has(pair.first) == has(pair.second), "incomplete ELF function array");
        if (has(pair.first)) {
            require(get(pair.second) % 8 == 0 && get(pair.second) / 8 <= max_entries, "invalid function array size");
            if (get(pair.second)) elf.file_at(get(pair.first), get(pair.second));
        }
    }
    return elf;
}
} // namespace epf::detail
