#include "elf2epf/converter.hpp"
#include <iostream>
#include <limits>
#include <set>
#ifdef _WIN32
#define NOMINMAX
#include <windows.h>
#endif

namespace {
constexpr const char* usage = R"(elf2epf 0.1.0 - x86-64 ELF to EPF v1.0

Usage:
  elf2epf convert INPUT -o OUTPUT --type exec|shared --profile FILE [options]
  elf2epf check INPUT --type exec|shared --profile FILE [options]
  elf2epf inspect FILE
  elf2epf verify FILE [--deps] [--library-path DIR ...]

Conversion options:
  --profile FILE          Read key=value target ABI configuration
  --os-abi NUMBER         Explicit OS ABI number (also usable without --profile)
  --abi-version NUMBER    Override ABI version (default: 1)
  --map-align NUMBER      Override mapping alignment (default: 4096)
  --interpreter PATH      Target EPF interpreter; never copied from ELF
  --soname NAME           Override module name for shared output
  --map-needed OLD=NEW    Rename a dependency (repeatable)

Output files must not already exist. Numbers accept decimal or 0x hexadecimal.
verify checks one file unless --deps or --library-path requests closure checks.
The input must already target your OS ABI; Linux syscall/CRT ABIs are not translated.
)";

std::uint64_t number(const std::string& text) {
    if (text.empty() || text.front() == '-' || text.front() == '+')
        throw epf::Error("E_ARGUMENT", "invalid unsigned number: " + text);
    std::size_t used = 0;
    try {
        auto value = std::stoull(text, &used, text.size() > 2 && text[0] == '0' &&
                               (text[1] == 'x' || text[1] == 'X') ? 16 : 10);
        if (used != text.size()) throw std::invalid_argument("trailing characters");
        return value;
    } catch (const std::logic_error&) { throw epf::Error("E_ARGUMENT", "invalid unsigned number: " + text); }
}
std::uint16_t number16(const std::string& text) {
    const auto n = number(text);
    if (n > UINT16_MAX) throw epf::Error("E_ARGUMENT", "number must fit uint16: " + text);
    return static_cast<std::uint16_t>(n);
}
int run(const std::vector<std::string>& args) {
    if (args.size() == 1 || (args.size() == 2 && (args[1] == "--help" || args[1] == "-h"))) {
        std::cout << usage; return 0;
    }
    if (args.size() == 2 && args[1] == "--version") { std::cout << "elf2epf 0.1.0\n"; return 0; }
    const auto& command = args[1];
    if (command != "convert" && command != "check" && command != "inspect" && command != "verify")
        throw epf::Error("E_ARGUMENT", "unknown command: " + command);
    const bool conversion = command == "convert" || command == "check";
    std::optional<std::filesystem::path> input, output, profile;
    std::optional<std::uint16_t> os_abi, abi_version;
    std::optional<std::uint64_t> alignment;
    std::optional<std::string> interpreter;
    epf::ConvertOptions options;
    bool type_seen = false, deps = false, positional_only = false;
    std::vector<std::filesystem::path> libraries;
    std::set<std::string> seen;
    for (std::size_t i = 2; i < args.size(); ++i) {
        auto key = args[i];
        if (!positional_only && key == "--") { positional_only = true; continue; }
        if (!positional_only && (key == "--help" || key == "-h")) { std::cout << usage; return 0; }
        if (!positional_only && !key.empty() && key.front() == '-') {
            if (key == "-o") key = "--output";
            if (key != "--map-needed" && key != "--library-path" && !seen.insert(key).second)
                throw epf::Error("E_ARGUMENT", "duplicate option: " + key);
            if (key == "--deps") {
                if (command != "verify") throw epf::Error("E_ARGUMENT", "--deps is only valid with verify");
                deps = true; continue;
            }
            if (key == "--library-path") {
                if (command != "verify") throw epf::Error("E_ARGUMENT", "--library-path is only valid with verify");
            } else if (!conversion) throw epf::Error("E_ARGUMENT", "option not valid with " + command + ": " + key);
            if (++i == args.size()) throw epf::Error("E_ARGUMENT", "missing value for " + key);
            const auto& value = args[i];
            if (key == "--type") {
                if (value != "exec" && value != "shared") throw epf::Error("E_ARGUMENT", "--type must be exec or shared");
                options.type = value == "exec" ? epf::FileType::exec : epf::FileType::shared; type_seen = true;
            } else if (key == "--output") output = std::filesystem::u8path(value);
            else if (key == "--profile") profile = std::filesystem::u8path(value);
            else if (key == "--os-abi") os_abi = number16(value);
            else if (key == "--abi-version") abi_version = number16(value);
            else if (key == "--map-align") alignment = number(value);
            else if (key == "--interpreter") interpreter = value;
            else if (key == "--soname") options.soname = value;
            else if (key == "--map-needed") {
                auto equal = value.find('=');
                if (equal == std::string::npos || equal == 0 || equal + 1 == value.size())
                    throw epf::Error("E_ARGUMENT", "--map-needed must be OLD=NEW");
                if (!options.needed_map.emplace(value.substr(0, equal), value.substr(equal + 1)).second)
                    throw epf::Error("E_ARGUMENT", "duplicate dependency mapping");
            } else if (key == "--library-path") { libraries.push_back(std::filesystem::u8path(value)); deps = true; }
            else throw epf::Error("E_ARGUMENT", "unknown option: " + key);
        } else {
            if (input) throw epf::Error("E_ARGUMENT", "only one input file is accepted");
            input = std::filesystem::u8path(args[i]);
        }
    }
    if (!input) throw epf::Error("E_ARGUMENT", "input file is required");
    if (conversion) {
        if (!type_seen) throw epf::Error("E_ARGUMENT", "--type exec|shared is required");
        if (command == "convert" && !output) throw epf::Error("E_ARGUMENT", "convert requires -o OUTPUT");
        if (command == "check" && output) throw epf::Error("E_ARGUMENT", "check does not accept an output path");
        if (profile) options.profile = epf::read_profile(*profile);
        if (os_abi) options.profile.os_abi = os_abi;
        if (abi_version) options.profile.abi_version = *abi_version;
        if (alignment) options.profile.map_align = *alignment;
        if (interpreter) options.profile.interpreter = *interpreter;
        auto image = epf::convert(epf::read_file(*input), options);
        if (output) {
            epf::write_file_atomic(*output, image.bytes);
            std::cout << "Created " << output->u8string() << " (" << image.bytes.size() << " bytes)\n";
        } else std::cout << "Conversion check passed (no file written)\n";
        std::cout << image.segments.size() << " segments, " << image.symbols.size() << " dynamic symbols, "
                  << image.relocations.size() << " runtime relocations\n";
    } else if (command == "inspect") {
        std::cout << epf::inspect(epf::decode(epf::read_file(*input)));
    } else if (deps) {
        auto count = epf::verify_dependencies(*input, libraries);
        std::cout << "EPF validation and dependency resolution passed (" << count << " modules)\n";
    } else {
        epf::decode(epf::read_file(*input));
        std::cout << "EPF validation passed (file only; use --deps to check dependencies)\n";
    }
    return 0;
}
int entry(const std::vector<std::string>& args) {
    try { return run(args); }
    catch (const epf::Error& error) {
        std::cerr << error.what() << '\n'; return error.code() == "E_ARGUMENT" ? 2 : 1;
    } catch (const std::filesystem::filesystem_error& error) {
        std::cerr << "E_IO: " << error.what() << '\n'; return 1;
    } catch (const std::bad_alloc&) {
        std::cerr << "E_RESOURCE: memory allocation failed\n"; return 1;
    } catch (const std::exception& error) {
        std::cerr << "E_INTERNAL: " << error.what() << '\n'; return 1;
    }
}
} // namespace

#ifdef _WIN32
int wmain(int argc, wchar_t** argv) {
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::string> args;
    for (int i = 0; i < argc; ++i) {
        int n = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, nullptr, 0, nullptr, nullptr);
        if (!n) { std::cerr << "E_ARGUMENT: invalid Unicode argument\n"; return 2; }
        std::string text(static_cast<std::size_t>(n), '\0');
        WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, text.data(), n, nullptr, nullptr);
        text.pop_back(); args.push_back(std::move(text));
    }
    return entry(args);
}
#else
int main(int argc, char** argv) { return entry(std::vector<std::string>(argv, argv + argc)); }
#endif
