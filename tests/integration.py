"""End-to-end tests using real GNU ELF producers and an independent EPF test loader.

Native code runs only in child processes. This loader tests conversion, not an OS
entry/stack/syscall ABI. It never creates writable+executable pages.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import random
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest


def uint(data, at, size=8):
    return int.from_bytes(data[at:at + size], "little")


def put(data, at, value, size=8):
    data[at:at + size] = int(value % (1 << (size * 8))).to_bytes(size, "little")


def align(value, page=4096):
    return (value + page - 1) & -page


def elf_segments(data):
    start, step, count = uint(data, 32), uint(data, 54, 2), uint(data, 56, 2)
    return [(start + i * step, struct.unpack_from("<IIQQQQQQ", data, start + i * step)) for i in range(count)]


def elf_file_at(data, va):
    for _, s in elf_segments(data):
        if s[0] == 1 and s[3] <= va < s[3] + s[5]:
            return s[2] + va - s[3]
    raise AssertionError(f"unmapped ELF VA {va:x}")


def elf_tags(data):
    for _, s in elf_segments(data):
        if s[0] == 2:
            result = {}
            for at in range(s[2], s[2] + s[5], 16):
                tag, val = struct.unpack_from("<QQ", data, at)
                if not tag:
                    break
                result.setdefault(tag, []).append((at, val))
            return result
    return {}


def elf_relocations(data):
    tags = elf_tags(data)
    for pointer, length in ((7, 8), (23, 2)):
        if pointer in tags:
            start = elf_file_at(data, tags[pointer][0][1])
            size = tags[length][0][1]
            for at in range(start, start + size, 24):
                offset, info, addend = struct.unpack_from("<QQq", data, at)
                yield at, offset, info & 0xffffffff, info >> 32, addend


def without_sections(data):
    data = bytearray(data)
    put(data, 40, 0)
    put(data, 58, 0, 2)
    put(data, 60, 0, 2)
    put(data, 62, 0, 2)
    return data


def rebase_elf(data, delta):
    """Shift all linked VAs without changing code's relative displacements."""
    result = bytearray(data)
    put(result, 24, uint(data, 24) + delta)
    for at, s in elf_segments(data):
        if s[0] not in (0, 3, 0x6474e551):
            put(result, at + 16, s[3] + delta)
            put(result, at + 24, s[4] + delta)
    for tag, entries in elf_tags(data).items():
        if tag in (3, 4, 5, 6, 7, 12, 13, 17, 23, 25, 26, 32, 36, 0x6ffffef5):
            for at, value in entries:
                put(result, at + 8, value + delta)
    for at, offset, kind, _, addend in elf_relocations(data):
        put(result, at, offset + delta)
        if kind in (8, 38):
            put(result, at + 16, addend + delta)
    shoff, shent, shnum = uint(data, 40), uint(data, 58, 2), uint(data, 60, 2)
    for i in range(shnum):
        at = shoff + i * shent
        kind, flags = uint(data, at + 4, 4), uint(data, at + 8)
        if flags & 2:
            put(result, at + 16, uint(data, at + 16) + delta)
        if kind in (2, 11):
            for symbol in range(uint(data, at + 24), uint(data, at + 24) + uint(data, at + 32), 24):
                section = uint(data, symbol + 6, 2)
                if section and section < 0xff00:
                    put(result, symbol + 8, uint(data, symbol + 8) + delta)
    return result


class Epf:
    """Independent, deliberately small decoder used only on tool-validated output."""
    def __init__(self, path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        assert d[:4] == b"$EPF"
        self.kind = uint(d, 8, 2)
        self.flags = uint(d, 16, 4)
        self.features = uint(d, 24)
        self.preferred = uint(d, 32)
        self.entry = uint(d, 40)
        self.size = uint(d, 48)
        self.page = uint(d, 96)
        self.segments = []
        start = uint(d, 56)
        for i in range(uint(d, 80, 4)):
            at = start + i * 64
            values = struct.unpack_from("<IIQQQQQQQ", d, at)
            self.segments.append(dict(zip(("type", "flags", "file", "rva", "filesz", "memsz", "align", "r0", "r1"), values), at=at))
        self.tags, self.tag_at = {}, {}
        for s in self.segments:
            if s["type"] == 2:
                for at in range(s["file"], s["file"] + s["filesz"], 16):
                    tag, _, value = struct.unpack_from("<IIQ", d, at)
                    if tag == 0:
                        break
                    self.tags.setdefault(tag, []).append(value)
                    self.tag_at.setdefault(tag, []).append(at)
        self.symbols = []
        if 3 in self.tags:
            at = self.file_at(self.tag(3))
            for i in range(self.tag(4)):
                pos = at + i * 32
                name, section, value, size, binding, typ, visibility, domain, reserved = struct.unpack_from("<IIQQBBBBI", d, pos)
                self.symbols.append(dict(name=self.string(name), value=value, size=size, binding=binding,
                                         type=typ, visibility=visibility, domain=domain, at=pos))
        self.relocations = []
        if 6 in self.tags:
            at = self.file_at(self.tag(6))
            for i in range(self.tag(7)):
                pos = at + i * 32
                offset, addend, symbol, kind, reserved = struct.unpack_from("<QqIIQ", d, pos)
                self.relocations.append(dict(offset=offset, addend=addend, symbol=symbol, type=kind, at=pos))
        self.needed = [self.string(n) for n in self.tags.get(9, [])]
        self.init = self.array(11, 12)
        self.fini = self.array(13, 14)
        self.base = 0
        self.dependencies = []

    def tag(self, number):
        return self.tags[number][0]

    def file_at(self, rva):
        for s in self.segments:
            if s["type"] == 1 and s["rva"] <= rva < s["rva"] + s["filesz"]:
                return s["file"] + rva - s["rva"]
        raise AssertionError(f"RVA not file-backed: {rva:x}")

    def string(self, offset):
        start = self.file_at(self.tag(1)) + offset
        return self.data[start:self.data.index(0, start)].decode()

    def array(self, address, count):
        if address not in self.tags:
            return []
        return list(struct.unpack_from("<" + "Q" * self.tag(count), self.data, self.file_at(self.tag(address))))


def native_test(root_path, actions):
    """Load generated EPFs, relocate, apply final permissions, then call C ABI functions."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.mmap.restype = ctypes.c_void_p
    libc.mmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_size_t]
    libc.mprotect.argtypes = [ctypes.c_void_p, ctypes.c_size_t, ctypes.c_int]
    libc.munmap.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
    modules = {}

    def load(path):
        path = Path(path).resolve()
        if path in modules:
            return modules[path]
        image = Epf(path)
        modules[path] = image
        for name in image.needed:
            image.dependencies.append(load(path.parent / name))
        return image

    root = load(root_path)
    for image in modules.values():
        alignment = max(s["align"] for s in image.segments if s["type"] == 1)
        if image.kind == 2 and not image.flags & 1:
            image.base = libc.mmap(image.preferred, image.size, 0, 0x100022, -1, 0)
            assert image.base == image.preferred, ("fixed mmap", ctypes.get_errno())
        else:
            raw = libc.mmap(None, image.size + alignment, 0, 0x22, -1, 0)
            assert raw != ctypes.c_void_p(-1).value, ctypes.get_errno()
            image.base = align(raw, alignment)
            if image.base > raw:
                assert libc.munmap(raw, image.base - raw) == 0
            tail = raw + image.size + alignment - image.base - image.size
            if tail:
                assert libc.munmap(image.base + image.size, tail) == 0
        for s in image.segments:
            if s["type"] != 1:
                continue
            addr = image.base + s["rva"]
            assert libc.mprotect(addr, align(s["memsz"], image.page), 3) == 0
            ctypes.memmove(addr, image.data[s["file"]:s["file"] + s["filesz"]], s["filesz"])
            assert ctypes.string_at(addr + s["filesz"], s["memsz"] - s["filesz"]) == bytes(s["memsz"] - s["filesz"])
            tail = align(s["memsz"], image.page) - s["memsz"]
            assert ctypes.string_at(addr + s["memsz"], tail) == bytes(tail)

    def resolve(image, symbol):
        if symbol["domain"] == 2:
            return image.base + symbol["value"]
        if symbol["domain"] == 3:
            return symbol["value"]
        queue = list(image.dependencies)
        seen, weak = {image.path.resolve()}, None
        for candidate in queue:
            if candidate.path.resolve() in seen:
                continue
            seen.add(candidate.path.resolve())
            for definition in candidate.symbols:
                if definition["name"] != symbol["name"] or definition["domain"] == 0 or definition["visibility"]:
                    continue
                if definition["binding"] == 1:
                    return resolve(candidate, definition)
                if definition["binding"] == 2 and weak is None:
                    weak = resolve(candidate, definition)
            queue.extend(candidate.dependencies)
        if weak is not None:
            return weak
        assert symbol["binding"] == 2, f"unresolved {symbol['name']}"
        return 0

    for image in modules.values():
        for rel in image.relocations:
            kind, addend, where = rel["type"], rel["addend"], image.base + rel["offset"]
            if not kind:
                continue
            if kind in (4, 5):
                value = image.base + addend
            else:
                symbol = resolve(image, image.symbols[rel["symbol"]]) if rel["symbol"] else 0
                value = symbol + addend - (where if kind == 3 else 0)
            if kind in (1, 4):
                assert 0 <= value < 1 << 32
                ctypes.c_uint32.from_address(where).value = value
            elif kind == 3:
                assert -(1 << 31) <= value < 1 << 31
                ctypes.c_int32.from_address(where).value = value
            else:
                assert 0 <= value < 1 << 64
                ctypes.c_uint64.from_address(where).value = value
        for s in image.segments:
            if s["type"] == 1:
                protection = s["flags"] & 7  # EPF bits match Linux PROT_READ/WRITE/EXEC.
                assert protection != 7
                assert libc.mprotect(image.base + s["rva"], align(s["memsz"], image.page), protection) == 0
            elif s["type"] == 5:
                assert libc.mprotect(image.base + s["rva"], s["memsz"], 1) == 0
    initialized = []

    def initialize(image):
        if image in initialized:
            return
        for dep in image.dependencies:
            initialize(dep)
        for rva in image.init:
            ctypes.CFUNCTYPE(None)(image.base + rva)()
        initialized.append(image)

    initialize(root)
    for action in actions:
        if action[0] == "fini":
            for image in reversed(initialized):
                for rva in reversed(image.fini):
                    ctypes.CFUNCTYPE(None)(image.base + rva)()
        elif action[0] == "entry":
            assert ctypes.CFUNCTYPE(ctypes.c_int)(root.base + root.entry)() == action[1]
        else:
            _, name, arguments, expected = action
            symbol = next(s for s in root.symbols if s["name"] == name and s["domain"] != 0)
            function = ctypes.CFUNCTYPE(ctypes.c_int, *([ctypes.c_int] * len(arguments)))(resolve(root, symbol))
            actual = function(*arguments)
            assert actual == expected, (name, actual, expected)


class Integration(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="elf2epf-tests-")
        cls.work = Path(cls.temp.name)
        cls.tool = Path(ARGS.tool).resolve()
        cls.cc, cls.ld = ARGS.cc, ARGS.ld
        cls.profile = cls.work / "target.ini"
        cls.profile.write_text("os_abi=0x8000\nabi_version=1\nmap_align=4096\ninterpreter=/system/ld-epf.epf\n")
        cls.static = cls.assembly("fixed", """
            .global _start
            .text
            _start: mov number(%rip), %eax
                    add zeros+16384(%rip), %eax
                    ret
            .data
            number: .long 42
            .bss
            .balign 16
            zeros: .skip 16388
            .section .note.GNU-stack,"",@progbits
        """, ["-static", "-Ttext-segment=0x10000000"])
        cls.pie = cls.assembly("pie", """
            .global _start
            .text
            _start: mov pointer(%rip), %rax
                    mov (%rax), %eax
                    ret
            .data
            number: .quad 42
            pointer: .quad number
            .section .note.GNU-stack,"",@progbits
        """, ["-pie", "--no-dynamic-linker", "--hash-style=gnu"])
        cls.base = cls.shared("base", """
            int seed = 7;
            int *seed_ptr = &seed;
            int add(int x) { return seed + x; }
            int get_ptr(void) { return *seed_ptr; }
            int unused_export(void) { return 91; }
        """)
        cls.consumer = cls.shared("consumer", """
            extern int add(int);
            extern int missing(void) __attribute__((weak));
            static int state;
            __attribute__((constructor)) static void start(void) { state = 3; }
            __attribute__((destructor)) static void stop(void) { state = 9; }
            int compute(int x) { return add(x) + state + (missing ? missing() : 0); }
            int state_value(void) { return state; }
        """, [cls.base])

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    @classmethod
    def command(cls, command):
        result = subprocess.run([str(v) for v in command], capture_output=True, text=True, timeout=15)
        if result.returncode:
            raise AssertionError(f"{command}\n{result.stdout}\n{result.stderr}")
        return result

    @classmethod
    def assembly(cls, name, source, flags):
        path = cls.work / (name + ".S")
        path.write_text(source)
        obj, output = path.with_suffix(".o"), path.with_suffix(".elf")
        cls.command([cls.cc, "-c", path, "-o", obj])
        cls.command([cls.ld, *flags, "-e", "_start", "-z", "noexecstack", obj, "-o", output])
        return output

    @classmethod
    def shared(cls, name, source, dependencies=(), extra=()):
        path = cls.work / (name + ".c")
        path.write_text(source)
        output = cls.work / ("lib" + name + ".so")
        cls.command([cls.cc, "-fPIC", "-fcf-protection=none", "-fno-stack-protector", "-fno-asynchronous-unwind-tables",
                     "-nostdlib", "-shared", path, "-Wl,-Bsymbolic,-z,now,-z,noexecstack,--hash-style=gnu",
                     "-Wl,-soname," + output.name, "-Wl,--no-as-needed", *dependencies, *extra, "-o", output])
        return output

    def invoke(self, *args, fail=None):
        result = subprocess.run([str(self.tool), *map(str, args)], capture_output=True, text=True, timeout=10)
        if fail is None:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else:
            self.assertGreater(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(fail, result.stderr)
        return result

    def convert(self, source, name, kind="shared", extra=()):
        output = self.work / name
        if output.exists():
            output.unlink()
        self.invoke("convert", source, "-o", output, "--type", kind, "--profile", self.profile, *extra)
        return output

    def native(self, path, actions):
        if platform.machine().lower() not in ("x86_64", "amd64"):
            self.skipTest("native execution needs an x86-64 host")
        result = subprocess.run([sys.executable, __file__, "--native", str(path), json.dumps(actions)],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, f"native loader exited {result.returncode}\n{result.stdout}\n{result.stderr}")

    def test_fixed_exec_bss_and_native_entry(self):
        output = self.convert(self.static, "fixed.epf", "exec")
        image = Epf(output)
        self.assertEqual((image.kind, image.flags, image.features), (2, 0, 0))
        self.assertEqual(image.preferred + image.entry, uint(self.static.read_bytes(), 24))
        self.assertEqual(uint(image.data, 84, 4), 0)
        self.native(output, [["entry", 42]])
        self.invoke("verify", output)
        self.assertIn("EXEC", self.invoke("inspect", output).stdout)
        for _, load in elf_segments(self.static.read_bytes()):
            if load[0] == 1 and load[5]:
                offset = Epf(output).file_at(load[3] - image.preferred)
                self.assertEqual(image.data[offset:offset + load[5]], self.static.read_bytes()[load[2]:load[2] + load[5]])

    def test_static_pie_and_nonzero_origin(self):
        for delta in (0, 0x200000):
            with self.subTest(origin=delta):
                source = self.pie
                if delta:
                    source = self.work / "rebased.elf"
                    source.write_bytes(rebase_elf(self.pie.read_bytes(), delta))
                output = self.convert(source, f"pie-{delta}.epf", "exec")
                image = Epf(output)
                self.assertEqual((image.flags, image.preferred), (1, 0))
                self.assertEqual(image.features & 3, 1)
                self.assertTrue(image.relocations)
                self.assertTrue(all(r["type"] == 5 for r in image.relocations))
                self.native(output, [["entry", 42]])

    def test_shared_exports_and_relative_pointers(self):
        output = self.convert(self.base, "base.eps", extra=["--soname", "base.eps"])
        image = Epf(output)
        self.assertEqual((image.kind, image.flags, image.preferred, image.entry), (3, 0, 0, (1 << 64) - 1))
        self.assertEqual(image.string(image.tag(10)), "base.eps")
        self.assertNotIn(3, [s["type"] for s in image.segments])
        self.native(output, [["call", "add", [5], 12], ["call", "get_ptr", [], 7]])

    def test_imports_constructors_relro_and_dependency_check(self):
        self.convert(self.base, "libbase.eps", extra=["--soname", "libbase.eps"])
        output = self.convert(self.consumer, "consumer.eps", extra=["--map-needed", "libbase.so=libbase.eps"])
        image = Epf(output)
        self.assertEqual(image.needed, ["libbase.eps"])
        self.assertTrue(image.init and image.fini)
        self.assertTrue(image.features & 8)
        self.invoke("verify", output, "--deps")
        self.native(output, [["call", "compute", [5], 15], ["call", "state_value", [], 3], ["fini"], ["call", "state_value", [], 9]])

    def test_dynamic_executable_interpreter(self):
        source = self.assembly("dynamic", """
            .global _start
            .text
            _start: mov $5, %edi
                    sub $8, %rsp
                    call add@PLT
                    add $8, %rsp
                    ret
            .section .note.GNU-stack,"",@progbits
        """, ["-pie", "--dynamic-linker", "/old/elf-loader", "--no-as-needed", str(self.base)])
        self.convert(self.base, "libbase.eps")
        output = self.convert(source, "dynamic.epf", "exec", ["--map-needed", "libbase.so=libbase.eps"])
        image = Epf(output)
        interp = next(s for s in image.segments if s["type"] == 3)
        self.assertEqual(image.data[interp["file"]:interp["file"] + interp["filesz"]], b"/system/ld-epf.epf\0")
        self.invoke("verify", output, "--deps")
        self.native(output, [["entry", 12]])

    def test_sectionless_gnu_and_sysv_hash(self):
        sysv = self.shared("sysv", "int unused_export(void) { return 91; }", extra=["-Wl,--hash-style=sysv"])
        both = self.shared("both", "int unused_export(void) { return 91; }", extra=["-Wl,--hash-style=both"])
        for source in (self.base, sysv, both):
            with self.subTest(source=source.name):
                stripped = self.work / (source.name + ".stripped")
                stripped.write_bytes(without_sections(source.read_bytes()))
                output = self.convert(stripped, source.name + ".eps")
                self.assertIn("unused_export", [s["name"] for s in Epf(output).symbols])
                self.native(output, [["call", "unused_export", [], 91]])

    def test_empty_gnu_hash_needs_an_authoritative_count(self):
        source = self.assembly("empty-hash", """
            .global _start
            .text
            _start: sub $8, %rsp
                    mov $5, %edi
                    call add@PLT
                    add $8, %rsp
                    ret
            .section .note.GNU-stack,"",@progbits
        """, ["-pie", "--no-dynamic-linker", "--hash-style=gnu", "--no-as-needed", str(self.base)])
        stripped = self.work / "empty-hash-stripped.elf"
        stripped.write_bytes(without_sections(source.read_bytes()))
        self.invoke("check", stripped, "--type", "exec", "--profile", self.profile, fail="cannot determine dynamic symbol count")
        # Keeping SHT_DYNSYM retains an exact count even though the hash is empty.
        self.invoke("check", source, "--type", "exec", "--profile", self.profile)

    def test_alignment_and_rebased_shared_image(self):
        high = self.shared("aligned", "int value(void) { return 17; }", extra=["-Wl,-z,max-page-size=2097152"])
        page64 = self.shared("page64", "int value(void) { return 17; }", extra=["-Wl,-z,max-page-size=65536"])
        for source, alignment, name in ((high, 4096, "aligned.eps"), (page64, 65536, "page64.eps")):
            output = self.convert(source, name, extra=["--map-align", alignment])
            image = Epf(output)
            self.assertEqual(image.page, alignment)
            self.assertEqual(max(s["align"] for s in image.segments if s["type"] == 1), 2097152 if source == high else 65536)
            self.native(output, [["call", "value", [], 17]])
        source = self.work / "rebased-base.so"
        source.write_bytes(rebase_elf(self.base.read_bytes(), 0x200000))
        output = self.convert(source, "rebased-base.eps")
        self.native(output, [["call", "get_ptr", [], 7], ["call", "unused_export", [], 91]])

    def test_runtime_pcrel32_data_and_absolute_symbol(self):
        source = self.assembly("pcrel", """
            .global _start, read_seed, absolute_value
            .set absolute_value, 1234
            .text
            _start:
            read_seed:
                lea displacement(%rip), %rax
                movslq (%rax), %rdx
                add %rax, %rdx
                mov (%rdx), %eax
                ret
            .data
            displacement: .long seed - .
            .section .note.GNU-stack,"",@progbits
        """, ["-shared", "-Bsymbolic", "--no-as-needed", str(self.base)])
        self.convert(self.base, "libbase.eps")
        output = self.convert(source, "pcrel.eps", extra=["--map-needed", "libbase.so=libbase.eps"])
        image = Epf(output)
        self.assertIn(3, [r["type"] for r in image.relocations])
        absolute = next(s for s in image.symbols if s["name"] == "absolute_value")
        self.assertEqual((absolute["domain"], absolute["value"]), (3, 1234))
        self.native(output, [["call", "read_seed", [], 7]])

    def test_strong_dependency_beats_earlier_weak_definition(self):
        weak = self.shared("weak", "__attribute__((weak)) int pick(void) { return 1; }")
        strong = self.shared("strong", "int pick(void) { return 2; }")
        source = self.shared("choose", "extern int pick(void); int choose(void) { return pick(); }", [weak, strong])
        self.convert(weak, "weak.eps")
        self.convert(strong, "strong.eps")
        output = self.convert(source, "choose.eps", extra=["--map-needed", "libweak.so=weak.eps", "--map-needed", "libstrong.so=strong.eps"])
        self.assertEqual(Epf(output).needed, ["weak.eps", "strong.eps"])
        self.invoke("verify", output, "--deps")
        self.native(output, [["call", "choose", [], 2]])

    def test_symbol_only_relocations_ignore_elf_addend(self):
        data = bytearray(self.consumer.read_bytes())
        changed = set()
        for at, _, kind, _, _ in elf_relocations(data):
            if kind in (6, 7):
                put(data, at + 16, 123)
                changed.add(kind)
        self.assertEqual(changed, {6, 7})
        source = self.work / "nonzero-addends.so"
        source.write_bytes(data)
        self.convert(self.base, "libbase.eps")
        output = self.convert(source, "addends.eps", extra=["--map-needed", "libbase.so=libbase.eps"])
        self.assertTrue(all(r["addend"] == 0 for r in Epf(output).relocations if r["type"] == 2))
        self.native(output, [["call", "compute", [5], 15]])

    def test_legacy_init_fini_order(self):
        source = self.shared("callbacks", """
            static int log;
            void _init(void) { log = log * 10 + 1; }
            void _fini(void) { log = log * 10 + 3; }
            __attribute__((constructor)) static void begin(void) { log = log * 10 + 2; }
            __attribute__((destructor)) static void end(void) { log = log * 10 + 4; }
            int read_log(void) { return log; }
        """, extra=["-Wl,-init,_init,-fini,_fini"])
        output = self.convert(source, "callbacks.eps")
        self.assertEqual((len(Epf(output).init), len(Epf(output).fini)), (2, 2))
        self.native(output, [["call", "read_log", [], 12], ["fini"], ["call", "read_log", [], 1243]])

    def test_zero_entry_is_valid(self):
        data = bytearray(0x1006)
        data[:7] = b"\x7fELF\x02\x01\x01"
        put(data, 16, 2, 2); put(data, 18, 62, 2); put(data, 20, 1, 4)
        put(data, 32, 64); put(data, 52, 64, 2); put(data, 54, 56, 2); put(data, 56, 1, 2)
        struct.pack_into("<IIQQQQQQ", data, 64, 1, 5, 0x1000, 0, 0, 6, 6, 4096)
        data[0x1000:] = b"\xb8\x2a\x00\x00\x00\xc3"
        source = self.work / "zero-entry.elf"
        source.write_bytes(data)
        output = self.convert(source, "zero-entry.epf", "exec")
        self.assertEqual(Epf(output).entry, 0)
        self.invoke("verify", output)

    def test_target_selection_and_unsupported_features(self):
        self.invoke("check", self.static, "--type", "shared", "--profile", self.profile, fail="E_TARGET")
        self.invoke("check", self.static, "--type", "exec", fail="OS ABI")
        tls = self.shared("tls", "__thread int slot; int value(void) { return slot; }")
        self.invoke("check", tls, "--type", "shared", "--profile", self.profile, fail="TLS")
        for kind, name in ((5, "COPY"), (11, "32S"), (37, "IRELATIVE")):
            data = bytearray(self.pie.read_bytes())
            at, _, _, symbol, _ = next(elf_relocations(data))
            # Remove the RELACOUNT optimization so the unsupported relocation reaches the converter.
            for pos, value in elf_tags(data).get(0x6ffffff9, []):
                put(data, pos + 8, 0)
            put(data, at + 8, (symbol << 32) | kind)
            source = self.work / ("unsupported-" + name + ".elf")
            source.write_bytes(data)
            self.invoke("check", source, "--type", "exec", "--profile", self.profile, fail=name)

    def test_unsupported_runtime_metadata(self):
        ifunc = self.shared("ifunc", """
            static int impl(void) { return 1; }
            static void *resolver(void) { return impl; }
            int value(void) __attribute__((ifunc("resolver")));
        """)
        self.invoke("check", ifunc, "--type", "shared", "--profile", self.profile, fail="IFUNC")
        cet = self.shared("cet", "int value(void) { return 1; }", extra=["-fcf-protection=full"])
        self.invoke("check", cet, "--type", "shared", "--profile", self.profile, fail="CET")
        version = self.work / "versions.map"
        version.write_text("V1 { global: value; local: *; };\n")
        versioned = self.shared("versioned", "int value(void) { return 1; }", extra=["-Wl,--version-script=" + str(version)])
        self.invoke("check", versioned, "--type", "shared", "--profile", self.profile, fail="symbol versioning")
        packed = self.shared("packed", "int n; int *p = &n;", extra=["-Wl,-z,pack-relative-relocs"])
        self.invoke("check", packed, "--type", "shared", "--profile", self.profile, fail="REL/RELR")
        stack = self.shared("execstack", "int value(void) { return 1; }", extra=["-Wl,-z,execstack"])
        self.invoke("check", stack, "--type", "shared", "--profile", self.profile, fail="executable stack")

    def test_layout_rejections(self):
        for what in ("wx", "overlap", "relro"):
            source = self.base if what == "relro" else self.static
            data = bytearray(source.read_bytes())
            if what == "relro":
                at, s = next((at, s) for at, s in elf_segments(data) if s[0] == 0x6474e552)
                put(data, at + 16, s[3] + 8); put(data, at + 40, s[6] - 8)
            else:
                at, s = next((at, s) for at, s in elf_segments(data) if s[0] == 1 and s[1] & 1)
                if what == "wx":
                    put(data, at + 4, 7, 4)
                else:
                    put(data, at + 16, uint(data, 24) - 0x800)
                    put(data, at + 48, 1)
                    put(data, 24, uint(data, 24) - 0x800)
            path = self.work / (what + ".elf")
            path.write_bytes(data)
            self.invoke("check", path, "--type", "shared" if what == "relro" else "exec", "--profile", self.profile, fail="E_LAYOUT")

    def test_dependencies_missing_abi_and_unresolved(self):
        self.convert(self.base, "libbase.eps")
        root = self.convert(self.consumer, "dependencies.eps", extra=["--map-needed", "libbase.so=libbase.eps"])
        isolated = self.work / "isolated"
        isolated.mkdir(exist_ok=True)
        copy = isolated / "consumer.eps"
        shutil.copyfile(root, copy)
        self.invoke("verify", copy, "--deps", fail="cannot find")
        self.invoke("verify", copy, "--library-path", self.work)
        dependency = bytearray((self.work / "libbase.eps").read_bytes())
        put(dependency, 12, 12, 2)
        (isolated / "libbase.eps").write_bytes(dependency)
        self.invoke("verify", copy, "--deps", fail="E_ABI")
        source = self.shared("unresolved", "extern int absent(void); int value(void) { return absent(); }")
        output = self.convert(source, "unresolved.eps")
        self.invoke("verify", output)
        self.invoke("verify", output, "--deps", fail="unresolved strong symbol")

    def test_dependency_cycles(self):
        b = self.shared("cycle_b", "int fb(void) { return 1; }")
        a = self.shared("cycle_a", "extern int fb(void); int fa(void) { return fb(); }", [b])
        b = self.shared("cycle_b", "extern int fa(void); int fb(void) { return fa(); }", [a])
        outa = self.convert(a, "cycle_a.eps", extra=["--map-needed", "libcycle_b.so=cycle_b.eps"])
        self.convert(b, "cycle_b.eps", extra=["--map-needed", "libcycle_a.so=cycle_a.eps"])
        self.invoke("verify", outa, "--deps", fail="cycle")

    def test_deterministic_check_unicode_and_output_protection(self):
        before = set(self.work.iterdir())
        self.invoke("check", self.static, "--type", "exec", "--profile", self.profile)
        self.assertEqual(before, set(self.work.iterdir()))
        first = self.convert(self.static, "first.epf", "exec")
        second = self.convert(self.static, "中文程序.epf", "exec")
        self.assertEqual(first.read_bytes(), second.read_bytes())
        original = second.read_bytes()
        self.invoke("convert", self.static, "-o", second, "--type", "exec", "--profile", self.profile, fail="already exists")
        self.assertEqual(second.read_bytes(), original)
        self.assertFalse(list(self.work.glob("*.tmp-*")))
        self.invoke("inspect", second)

    def test_bad_epf_ranges_metadata_and_relocations(self):
        output = self.convert(self.consumer, "mutations.eps")
        image = Epf(output)
        first_load = next(s for s in image.segments if s["type"] == 1)
        code_load = next(s for s in image.segments if s["type"] == 1 and s["flags"] & 4)
        data_load = next(s for s in image.segments if s["type"] == 1 and s["flags"] & 2)
        rel = image.relocations[0]
        cases = {
            "reserved": (108, 1, 1),
            "feature": (24, 1 << 63, 8),
            "missing-reloc-feature": (24, image.features & ~1, 8),
            "table-range": (56, (1 << 64) - 8, 8),
            "huge-count": (80, 0xffffffff, 4),
            "wx": (code_load["at"] + 4, 0x80000007, 4),
            "load-align": (first_load["at"] + 40, 3, 8),
            "load-range": (first_load["at"] + 32, (1 << 64) - 1, 8),
            "unknown-rel": (rel["at"] + 20, 99, 4),
            "rel-index": (rel["at"] + 16, len(image.symbols) + 1, 4),
            "rel-code": (rel["at"], code_load["rva"], 8),
            "rel-cross-end": (rel["at"], data_load["rva"] + data_load["memsz"] - 1, 8),
            "rel-self": (rel["at"], image.tag(6), 8),
            "rel-reserved": (rel["at"] + 24, 1, 8),
            "relative-symbol": (next(r for r in image.relocations if r["type"] == 5)["at"] + 16, 1, 4),
            "str-size": (image.tag_at[2][0] + 8, (1 << 64) - 1, 8),
            "symbol-name": (image.symbols[1]["at"], 0xffffffff, 4),
            "symbol-section": (image.symbols[1]["at"] + 4, 1, 4),
            "symbol-domain": (image.symbols[1]["at"] + 27, 1, 1),
            "symbol-reserved": (image.symbols[1]["at"] + 28, 1, 4),
            "init-data": (image.file_at(image.tag(11)), data_load["rva"], 8),
            "misaligned-table": (image.tag_at[3][0] + 8, image.tag(3) + 1, 8),
        }
        for name, (at, value, size) in cases.items():
            with self.subTest(case=name):
                data = bytearray(image.data)
                put(data, at, value, size)
                bad = self.work / "invalid.eps"
                bad.write_bytes(data)
                self.invoke("verify", bad, fail="E_")
        for at, value in ((image.tag_at[2][0], 1), (image.tag_at[2][0], 99)):
            data = bytearray(image.data)
            put(data, at, value, 4)
            bad.write_bytes(data)
            self.invoke("verify", bad, fail="E_")
        data = bytearray(image.data)
        put(data, image.relocations[1]["at"], rel["offset"])
        bad.write_bytes(data)
        self.invoke("verify", bad, fail="overlap")

    def test_dynamic_terminator_and_optional_unknown_tag(self):
        output = self.convert(self.base, "tags.eps")
        image = Epf(output)
        dynamic = next(s for s in image.segments if s["type"] == 2)
        data = bytearray(image.data)
        put(data, dynamic["file"] + dynamic["filesz"] - 16, 99, 4)
        bad = self.work / "unterminated.eps"
        bad.write_bytes(data)
        self.invoke("verify", bad, fail="NULL terminator")
        data = bytearray(image.data)
        put(data, image.tag_at[10][0], 99, 4)
        put(data, image.tag_at[10][0] + 4, 0, 4)
        optional = self.work / "optional-tag.eps"
        optional.write_bytes(data)
        self.invoke("verify", optional)

    def test_profile_and_argument_validation(self):
        for text, message in (("os_abi=1\nos_abi=2\n", "duplicate"), ("os_abi=65536\n", "uint16"),
                              ("os_abi=1\nunknown=2\n", "unknown profile key")):
            profile = self.work / "bad.ini"
            profile.write_text(text)
            self.invoke("check", self.static, "--type", "exec", "--profile", profile, fail=message)
        self.invoke("check", self.static, "--type", "exec", "--profile", self.profile, "--map-align", "3", fail="map_align")
        self.invoke("check", self.consumer, "--type", "shared", "--os-abi", "1", "--map-needed", "libbase.so=../bad", fail="single filename")
        self.invoke("check", self.consumer, "--type", "exec", "--os-abi", "1", fail="entry")

    def test_bounded_malformed_input_smoke(self):
        output = self.convert(self.base, "fuzz-seed.eps")
        rng = random.Random(20261109)
        for mode, seed in (("check", self.pie.read_bytes()), ("verify", output.read_bytes())):
            for i in range(80):
                data = bytearray(seed)
                if i < 16:
                    data = data[:i * 8]
                else:
                    for _ in range(rng.randint(1, 4)):
                        at = rng.randrange(len(data))
                        data[at] ^= rng.randrange(1, 256)
                path = self.work / "fuzz-input.bin"
                path.write_bytes(data)
                args = [mode, path]
                if mode == "check":
                    args += ["--type", "exec", "--profile", self.profile]
                result = subprocess.run([str(self.tool), *map(str, args)], capture_output=True, text=True, timeout=5)
                self.assertIn(result.returncode, (0, 1, 2), result.stderr)
                self.assertNotIn("E_INTERNAL", result.stderr)
                self.assertNotIn("runtime error:", result.stderr)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--native":
        native_test(sys.argv[2], json.loads(sys.argv[3]))
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument("--tool", required=True)
        parser.add_argument("--cc", default="cc")
        parser.add_argument("--ld", default="ld")
        ARGS, remaining = parser.parse_known_args()
        unittest.main(argv=[sys.argv[0], *remaining], verbosity=2)
