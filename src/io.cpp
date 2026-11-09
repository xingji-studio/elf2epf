#include "internal.hpp"
#include <chrono>
#include <fstream>
#include <random>
#include <set>

namespace epf {
using namespace detail;
Bytes read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) fail("E_IO", "cannot open " + path.u8string());
    auto length = input.tellg();
    if (length < 0 || static_cast<std::uint64_t>(length) > max_file)
        fail("E_RESOURCE", "file exceeds 256 MiB limit or its size cannot be read: " + path.u8string());
    Bytes bytes(static_cast<std::size_t>(length));
    input.seekg(0);
    if (!bytes.empty() && !input.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size())))
        fail("E_IO", "cannot read " + path.u8string());
    return bytes;
}

void write_file_atomic(const std::filesystem::path& path, const Bytes& bytes) {
    std::error_code ec;
    if (std::filesystem::exists(path, ec) || std::filesystem::is_symlink(path, ec))
        fail("E_IO", "output already exists; choose a new output path: " + path.u8string());
    auto temp = path;
    const auto nonce = std::chrono::steady_clock::now().time_since_epoch().count();
    std::random_device random;
    temp += std::filesystem::u8path(".tmp-" + std::to_string(nonce) + "-" + std::to_string(random()));
    try {
        if (std::filesystem::exists(temp)) fail("E_IO", "temporary output collision");
        {
            std::ofstream output(temp, std::ios::binary | std::ios::trunc);
            if (!output || (!bytes.empty() && !output.write(reinterpret_cast<const char*>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()))))
                fail("E_IO", "cannot write temporary output " + temp.u8string());
            output.flush();
            if (!output) fail("E_IO", "cannot flush temporary output");
            output.close();
            if (!output) fail("E_IO", "cannot close temporary output");
        }
        // Creating a link commits the complete file without ever replacing an existing destination.
        // The temporary file is in the same directory/filesystem (NTFS and Unix support this).
        std::filesystem::create_hard_link(temp, path, ec);
        if (ec) fail("E_IO", "cannot atomically commit output (hard links required): " + ec.message());
        std::filesystem::remove(temp, ec);
    } catch (...) {
        std::filesystem::remove(temp, ec);
        throw;
    }
}

namespace {
std::string trim(std::string text) {
    const auto start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return {};
    return text.substr(start, text.find_last_not_of(" \t\r\n") - start + 1);
}
std::uint64_t number(const std::string& text) {
    require(!text.empty() && text.front() != '-' && text.front() != '+', "invalid unsigned number: " + text);
    std::size_t used = 0;
    try {
        auto value = std::stoull(text, &used, text.size() > 2 && text[0] == '0' &&
                               (text[1] == 'x' || text[1] == 'X') ? 16 : 10);
        require(used == text.size(), "invalid unsigned number: " + text);
        return value;
    } catch (const std::logic_error&) { fail("E_ARGUMENT", "invalid unsigned number: " + text); }
}
} // namespace
TargetProfile read_profile(const std::filesystem::path& path) {
    const auto bytes = read_file(path);
    require(bytes.size() <= 65536, "profile exceeds 64 KiB limit");
    std::istringstream input(std::string(bytes.begin(), bytes.end()));
    TargetProfile profile;
    std::set<std::string> seen;
    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.empty() || line.front() == '#') continue;
        const auto equal = line.find('=');
        if (equal == std::string::npos) fail("E_ARGUMENT", "profile lines must be key=value");
        const auto key = trim(line.substr(0, equal)), value = trim(line.substr(equal + 1));
        if (!seen.insert(key).second) fail("E_ARGUMENT", "duplicate profile key: " + key);
        if (key == "os_abi" || key == "abi_version") {
            auto n = number(value);
            if (n > UINT16_MAX) fail("E_ARGUMENT", key + " must fit uint16");
            if (key == "os_abi") profile.os_abi = static_cast<std::uint16_t>(n);
            else profile.abi_version = static_cast<std::uint16_t>(n);
        } else if (key == "map_align") profile.map_align = number(value);
        else if (key == "interpreter") profile.interpreter = value;
        else fail("E_ARGUMENT", "unknown profile key: " + key);
    }
    return profile;
}
} // namespace epf
