#pragma once

#include "elf2epf/format.hpp"
#include <filesystem>
#include <map>
#include <stdexcept>

namespace epf {
class Error : public std::runtime_error {
public:
    Error(const std::string& code, const std::string& message)
        : std::runtime_error(code + ": " + message), code_(code) {}
    const std::string& code() const noexcept { return code_; }
private:
    std::string code_;
};
struct TargetProfile {
    // The OS ABI number must be explicitly supplied by the caller.
    std::optional<std::uint16_t> os_abi;
    std::uint16_t abi_version = 1;
    std::uint64_t map_align = 4096;
    std::string interpreter;
};
struct ConvertOptions {
    FileType type = FileType::exec;
    TargetProfile profile;
    std::optional<std::string> soname;
    std::map<std::string, std::string> needed_map;
};
Bytes read_file(const std::filesystem::path& path);
void write_file_atomic(const std::filesystem::path& path, const Bytes& bytes);
TargetProfile read_profile(const std::filesystem::path& path);
Image convert(const Bytes& elf, const ConvertOptions& options);
Image decode(const Bytes& bytes);
std::string inspect(const Image& image);
// Resolves each module's references in its own dependency closure, without executing code.
std::size_t verify_dependencies(const std::filesystem::path& root,
                               const std::vector<std::filesystem::path>& library_paths);
} // namespace epf
