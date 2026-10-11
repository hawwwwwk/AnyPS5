#include <relinker/parsing/ElfReader.hpp>
#include <cstdint>
#include <cstring>
#include <functional>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

using Bytes = std::vector<std::uint8_t>;

void require(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}

void requireFailure(const std::function<void()>& operation, const char* expected, const char* message) {
    try {
        operation();
    } catch (const Relinker::RelinkerException& error) {
        require(std::string(error.what()).find(expected) != std::string::npos, message);
        return;
    }
    throw std::runtime_error(message);
}

template<typename TValue>
void write(Bytes& bytes, std::size_t offset, TValue value) {
    if (offset > bytes.size() || sizeof(value) > bytes.size() - offset)
        throw std::runtime_error("Fixture write exceeds input");
    std::memcpy(bytes.data() + offset, &value, sizeof(value));
}

Bytes fixture(std::uint64_t segmentOffset, std::uint64_t virtualAddress, std::uint64_t fileSize, std::uint32_t type = 1) {
    Bytes bytes(0x300);
    bytes[0] = 0x7f;
    bytes[1] = 'E';
    bytes[2] = 'L';
    bytes[3] = 'F';
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    write<std::uint64_t>(bytes, 0x20, 0x40);
    write<std::uint16_t>(bytes, 0x36, 56);
    write<std::uint16_t>(bytes, 0x38, 1);
    write<std::uint32_t>(bytes, 0x40, type);
    write<std::uint64_t>(bytes, 0x48, segmentOffset);
    write<std::uint64_t>(bytes, 0x50, virtualAddress);
    write<std::uint64_t>(bytes, 0x60, fileSize);
    return bytes;
}

void testValidMappings() {
    const Relinker::ElfReader reader(fixture(0x100, 0x1000, 0x80));
    require(reader.TranslateVirtualAddress(0x1000) == 0x100, "Start of PT_LOAD mapped incorrectly");
    require(reader.TranslateVirtualAddress(0x1030) == 0x130, "Interior of PT_LOAD mapped incorrectly");
    require(reader.TranslateVirtualAddress(0x107f) == 0x17f, "Last file-backed byte of PT_LOAD mapped incorrectly");
    requireFailure([&] { (void)reader.TranslateVirtualAddress(0x1080); }, "Virtual address not mapped", "Address beyond PT_LOAD was mapped");
    const Relinker::ElfReader other(fixture(0x100, 0x1000, 0x80, 2));
    requireFailure([&] { (void)other.TranslateVirtualAddress(0x1000); }, "Virtual address not mapped", "Non-load segment was mapped");
    const Relinker::ElfReader toEnd(fixture(0x2e0, 0x4000, 0x20));
    require(toEnd.TranslateVirtualAddress(0x401f) == 0x2ff, "PT_LOAD ending exactly at EOF was rejected");
}

void testInvalidFileMappings() {
    const Relinker::ElfReader truncated(fixture(0x2f0, 0x1000, 0x20));
    requireFailure([&] { (void)truncated.TranslateVirtualAddress(0x1000); }, "PT_LOAD segment out of bounds", "Truncated PT_LOAD returned a file offset");
    const Relinker::ElfReader pastEnd(fixture(0x301, 0x1000, 0x20));
    requireFailure([&] { (void)pastEnd.TranslateVirtualAddress(0x1000); }, "PT_LOAD segment out of bounds", "PT_LOAD past EOF returned a file offset");
    const Relinker::ElfReader wrapped(fixture(std::numeric_limits<std::uint64_t>::max() - 8, 0x1000, 0x40));
    requireFailure([&] { (void)wrapped.TranslateVirtualAddress(0x1010); }, "PT_LOAD segment out of bounds", "Wrapped file offset was accepted");
    const Relinker::ElfReader high(fixture(0x100, std::numeric_limits<std::uint64_t>::max() - 31, 0x20));
    require(high.TranslateVirtualAddress(std::numeric_limits<std::uint64_t>::max() - 1) == 0x11e,
            "Valid high-address mapping was lost to virtual address overflow");
}

}

int main() {
    try {
        testValidMappings();
        testInvalidFileMappings();
        return 0;
    } catch (const std::exception& error) {
        std::cerr << "elf_virtual_address_bounds_tests: " << error.what() << '\n';
        return 1;
    }
}
