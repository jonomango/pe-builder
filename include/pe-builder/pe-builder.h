#pragma once

#include <fstream>
#include <vector>
#include <cstring>

#include <Windows.h>

namespace pb {

class pe_builder {
public:
  // Write the PE image to a file
  bool write(char const* path) const;

private:
  std::uint32_t file_alignment_    = 0x200;
  std::uint32_t section_alignment_ = 0x1000;
  std::uint64_t image_base_        = 0x140000000;
  std::uint64_t entrypoint_        = 0x0;

private:
  // Write the PE image to a buffer
  std::vector<std::uint8_t> write_buffer(char const* path) const;

  // Fill in the DOS header.
  void write_dos_header(PIMAGE_DOS_HEADER dos_header) const;

  // Fill in the NT header.
  void write_nt_header(PIMAGE_NT_HEADERS64 nt_header,
    std::uint32_t image_size, std::uint32_t headers_size) const;

  // Align an integer up to the specified alignment.
  static std::uint64_t align_integer(std::uint64_t value, std::uint64_t alignment);
};

// Write the PE image to a file
bool pe_builder::write(char const* const path) const {
  auto const contents = write_buffer(path);
  if (contents.empty())
    return false;

  std::ofstream file(path, std::ios::binary);
  if (!file)
    return false;

  file.write(reinterpret_cast<char const*>(contents.data()), contents.size());

  return true;
}

// Write the PE image to a buffer
std::vector<std::uint8_t> pe_builder::write_buffer(char const* const path) const {
  constexpr auto num_sections = 5;

  // This is the initial file size of the image, before we start adding the
  // raw section data. This value is aligned to the file alignment.
  std::uint32_t headers_size = 0;

  headers_size += sizeof(IMAGE_DOS_HEADER);
  headers_size += sizeof(IMAGE_NT_HEADERS64);

  // Each data block has its own section, while code blocks are all stored
  // in a single section.
  headers_size += sizeof(IMAGE_SECTION_HEADER) * num_sections;

  // Align to the file alignment.
  headers_size = align_integer(headers_size, file_alignment_);

  // Allocate a vector with enough space for the MS-DOS header, the PE header,
  // and the section headers.
  std::vector<std::uint8_t> contents(headers_size, 0);

  // Write the headers to the buffer.
  write_dos_header(reinterpret_cast<PIMAGE_DOS_HEADER>(&contents[0]));
  write_nt_header(reinterpret_cast<PIMAGE_NT_HEADERS64>(&contents[sizeof(IMAGE_DOS_HEADER)]),
    static_cast<std::uint32_t>(contents.size()), headers_size);

  return contents;
}

// Fill in the DOS header.
void pe_builder::write_dos_header(PIMAGE_DOS_HEADER const dos_header) const {
  std::memset(dos_header, 0, sizeof(*dos_header));
  dos_header->e_magic  = IMAGE_DOS_SIGNATURE;
  dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
}

// Fill in the NT header.
void pe_builder::write_nt_header(PIMAGE_NT_HEADERS64 const nt_header,
    std::uint32_t const image_size, std::uint32_t const headers_size) const {
  std::memset(nt_header, 0, sizeof(*nt_header));
  nt_header->Signature                                  = IMAGE_NT_SIGNATURE;
  nt_header->FileHeader.Machine                         = IMAGE_FILE_MACHINE_AMD64;
  nt_header->FileHeader.NumberOfSections                = 1;
  nt_header->FileHeader.SizeOfOptionalHeader            = sizeof(nt_header->OptionalHeader);
  nt_header->FileHeader.Characteristics                 = IMAGE_FILE_EXECUTABLE_IMAGE;
  nt_header->OptionalHeader.Magic                       = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt_header->OptionalHeader.AddressOfEntryPoint         = entrypoint_;
  nt_header->OptionalHeader.ImageBase                   = image_base_;
  nt_header->OptionalHeader.SectionAlignment            = section_alignment_;
  nt_header->OptionalHeader.FileAlignment               = file_alignment_;
  nt_header->OptionalHeader.MajorOperatingSystemVersion = 6;
  nt_header->OptionalHeader.MinorOperatingSystemVersion = 0;
  nt_header->OptionalHeader.MajorSubsystemVersion       = 6;
  nt_header->OptionalHeader.MinorSubsystemVersion       = 0;
  nt_header->OptionalHeader.Subsystem                   = IMAGE_SUBSYSTEM_WINDOWS_CUI;
  nt_header->OptionalHeader.DllCharacteristics          = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    | IMAGE_DLLCHARACTERISTICS_NX_COMPAT | IMAGE_DLLCHARACTERISTICS_NO_SEH;
  nt_header->OptionalHeader.SizeOfStackReserve          = 0x10000;
  nt_header->OptionalHeader.SizeOfStackCommit           = 0x1000;
  nt_header->OptionalHeader.SizeOfHeapReserve           = 0x10000;
  nt_header->OptionalHeader.SizeOfHeapCommit            = 0x1000;
  nt_header->OptionalHeader.NumberOfRvaAndSizes         = 16;
  nt_header->OptionalHeader.SizeOfImage                 = image_size;
  nt_header->OptionalHeader.SizeOfHeaders               = headers_size;

}

// Align an integer up to the specified alignment.
std::uint64_t pe_builder::align_integer(
    std::uint64_t const value, std::uint64_t const alignment) {
  auto const r = value % alignment;

  // Already aligned.
  if (r == 0)
    return value;
  
  return value + (alignment - r);
}

} // namespace pb
