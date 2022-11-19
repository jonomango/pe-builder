#pragma once

#include <fstream>
#include <vector>
#include <deque>
#include <cstring>
#include <assert.h>

#include <Windows.h>

namespace pb {

class pe_section {
public:
  // Set the name of this section (maximum of 8 characters).
  // This directly corresponds to IMAGE_SECTION_HEADER::Name.
  pe_section& name(char const* name);

  // Set the virtual padding to be added to the end of this section (all zeros).
  // This is pretty much VirtualSize - SizeOfRawData, if we ignore alignment.
  pe_section& padding(std::uint32_t value);

  // Set the characteristics of this section.
  // This directly corresponds to IMAGE_SECTION_HEADER::Characteristics.
  pe_section& characteristics(std::uint32_t value);

  // Get a reference to the raw data that makes up this section.
  std::vector<std::uint8_t>& data();

private:
  friend class pe_builder;

  // The index of this section in the section vector.
  std::size_t section_idx_ = 0;

  // This is null-terminated but the real section name wont be (only 8 bytes).
  char name_[9] = { 0 };

  // Raw data (not including padding).
  std::vector<std::uint8_t> data_ = {};

  std::uint32_t padding_         = 0;
  std::uint32_t characteristics_ = 0;
};

class pe_builder {
public:
  // Write the PE image to a file
  bool write(char const* path) const;

  // Set the section alignment.
  // This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::SectionAlignment.
  pe_builder& section_alignment(std::uint32_t alignment);

  // Set the file alignment.
  // This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::FileAlignment.
  pe_builder& file_alignment(std::uint32_t alignment);

  // Set the image base address.
  // This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::ImageBase.
  pe_builder& image_base(std::uint64_t address);

  // Set the entrypoint address.
  // This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::AddressOfEntryPoint.
  pe_builder& entrypoint(std::uint64_t address);

  // Set the subsystem type.
  // This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::Subsystem.
  pe_builder& subsystem(std::uint16_t value);

  // Set the file characteristics.
  // This directly corresponds to IMAGE_NT_HEADERS::FileHeader::Characteristics.
  pe_builder& file_characteristics(std::uint16_t value);

  // Append a new section to the PE image.
  pe_section& section();

  // Compute the virtual address of a section.
  std::uint64_t virtual_address(pe_section const& section) const;

  // Return the remaining number of sections that can be added until the
  // image header is resized (which will invalidate all previously computed
  // section virtual addresses. This value is usually way more than enough
  // unless you use a low section alignment.
  std::size_t sections_until_resize() const;

private:
  std::uint32_t section_alignment_    = 0x1000;
  std::uint32_t file_alignment_       = 0x200;
  std::uint64_t image_base_           = 0x140000000;
  std::uint64_t entrypoint_           = 0x0;
  std::uint16_t subsystem_            = IMAGE_SUBSYSTEM_WINDOWS_CUI;
  std::uint16_t file_characteristics_ = IMAGE_FILE_EXECUTABLE_IMAGE;

  // We need to use a deque so we don't invalidate any iterators.
  std::deque<pe_section> sections_ = {};

private:
  // Write the PE image to a buffer
  std::vector<std::uint8_t> write_buffer(char const* path) const;

  // Fill in the DOS header.
  void write_dos_header(PIMAGE_DOS_HEADER dos_header) const;

  // Fill in the NT header.
  void write_nt_header(PIMAGE_NT_HEADERS64 nt_header,
    std::uint32_t image_size, std::uint32_t headers_size) const;

  // Compute the (unaligned) headers size.
  static std::size_t compute_headers_size(std::size_t num_sections);

  // Align an integer up to the specified alignment.
  static std::uint64_t align_integer(std::uint64_t value, std::uint64_t alignment);
};

// Set the name of this section (maximum of 8 characters).
inline pe_section& pe_section::name(char const* const name) {
  if (!name) {
    std::memset(&name_, 0, sizeof(name_));
    return *this;
  }

  // This smells a little...
  strncpy_s(name_, name, 8);
  return *this;
}

// Set the virtual padding to be added to the end of this section (all zeros).
// This is pretty much VirtualSize - SizeOfRawData, if we ignore alignment.
inline pe_section& pe_section::padding(std::uint32_t const value) {
  padding_ = value;
  return *this;
}

// Set the characteristics of this section.
// This directly corresponds to IMAGE_SECTION_HEADER::Characteristics.
inline pe_section& pe_section::characteristics(std::uint32_t const value) {
  characteristics_ = value;
  return *this;
}

// Get a reference to the raw data that makes up this section.
inline std::vector<std::uint8_t>& pe_section::data() {
  return data_;
}

// Write the PE image to a file
inline bool pe_builder::write(char const* const path) const {
  auto const contents = write_buffer(path);
  if (contents.empty())
    return false;

  std::ofstream file(path, std::ios::binary);
  if (!file)
    return false;

  file.write(reinterpret_cast<char const*>(contents.data()), contents.size());

  return true;
}

// Set the section alignment.
// This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::SectionAlignment.
inline pe_builder& pe_builder::section_alignment(std::uint32_t const alignment) {
  section_alignment_ = alignment;
  return *this;
}

// Set the file alignment.
// This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::FileAlignment.
inline pe_builder& pe_builder::file_alignment(std::uint32_t const alignment) {
  file_alignment_ = alignment;
  return *this;
}

// Set the image base address.
// This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::ImageBase.
inline pe_builder& pe_builder::image_base(std::uint64_t const address) {
  image_base_ = address;
  return *this;
}

// Set the entrypoint address.
// This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::AddressOfEntryPoint.
inline pe_builder& pe_builder::entrypoint(std::uint64_t const address) {
  entrypoint_ = address;
  return *this;
}

// Set the subsystem type.
// This directly corresponds to IMAGE_NT_HEADERS::OptionalHeader::Subsystem.
inline pe_builder& pe_builder::subsystem(std::uint16_t const value) {
  subsystem_ = value;
  return *this;
}

// Set the file characteristics.
// This directly corresponds to IMAGE_NT_HEADERS::FileHeader::Characteristics.
inline pe_builder& pe_builder::file_characteristics(std::uint16_t const value) {
  file_characteristics_ = value;
  return *this;
}

// Append a new section to the PE image.
inline pe_section& pe_builder::section() {
  auto& sec = sections_.emplace_back();
  sec.section_idx_ = sections_.size() - 1;
  return sec;
}

// Compute the virtual address of a section.
inline std::uint64_t pe_builder::virtual_address(pe_section const& section) const {
  // This is the initial file size of the image, before we start adding the
  // raw section data. This value is aligned to the file alignment.
  auto const headers_size = align_integer(
    compute_headers_size(sections_.size()), file_alignment_);

  std::uint64_t current_rva = align_integer(
    static_cast<std::uint32_t>(headers_size), section_alignment_);

  for (std::size_t i = 0; i < sections_.size(); ++i) {
    if (i == section.section_idx_)
      return image_base_ + current_rva;

    auto const& sec = sections_[i];

    auto const aligned_size = align_integer(sec.data_.size(), file_alignment_);
    auto const virtual_padding = sec.padding_ - (aligned_size - sec.data_.size());
    
    current_rva = align_integer(current_rva +
      aligned_size + virtual_padding, section_alignment_);
  }

  return 0;
}

// Return the remaining number of sections that can be added until the
// image header is resized (which will invalidate all previously computed
// section virtual addresses. This value is usually way more than enough
// unless you use a low section alignment.
inline std::size_t pe_builder::sections_until_resize() const {
  auto const unaligned_hdr_size = compute_headers_size(sections_.size());
  return (align_integer(unaligned_hdr_size, section_alignment_)
    - unaligned_hdr_size) / sizeof(IMAGE_SECTION_HEADER);
}

// Write the PE image to a buffer
inline std::vector<std::uint8_t> pe_builder::write_buffer(char const* const path) const {
  // This is the initial file size of the image, before we start adding the
  // raw section data. This value is aligned to the file alignment.
  auto const headers_size = align_integer(
    compute_headers_size(sections_.size()), file_alignment_);

  // Allocate a vector with enough space for the MS-DOS header, the PE header,
  // and the section headers.
  std::vector<std::uint8_t> contents(headers_size, 0);

  std::uint64_t current_rva = align_integer(
    static_cast<std::uint32_t>(headers_size), section_alignment_);

  auto const section_hdrs = reinterpret_cast<PIMAGE_SECTION_HEADER>(
    &contents[sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)]);

  for (std::size_t i = 0; i < sections_.size(); ++i) {
    auto const& sec = sections_[i];

    assert(virtual_address(sec) == current_rva + image_base_);

    // This needs to be computed everytime since we're using a vector and it can resize.
    auto& hdr = reinterpret_cast<PIMAGE_SECTION_HEADER>(
      &contents[sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_NT_HEADERS64)])[i];

    std::memset(&hdr, 0, sizeof(hdr));
    std::memcpy(hdr.Name, sec.name_, 8);
    hdr.Characteristics  = sec.characteristics_;
    hdr.VirtualAddress   = static_cast<std::uint32_t>(current_rva);
    hdr.Misc.VirtualSize = static_cast<std::uint32_t>(sec.data_.size() + sec.padding_);
    hdr.SizeOfRawData    = static_cast<std::uint32_t>(
      align_integer(sec.data_.size(), file_alignment_));
    hdr.PointerToRawData = static_cast<std::uint32_t>(contents.size());

    // This needs to be stored before we add to the buffer.
    auto const aligned_size = hdr.SizeOfRawData;

    // Append the section data to the buffer.
    contents.insert(end(contents), begin(sec.data_), end(sec.data_));

    // We need to add padding so that we're aligned to the file alignment.
    if (aligned_size > sec.data_.size())
      contents.insert(end(contents), aligned_size - sec.data_.size(), 0);

    // This is how much virtual padding we need (since we added some real
    // padding when aligning to file alignment).
    auto const virtual_padding = sec.padding_ - (aligned_size - sec.data_.size());

    current_rva = align_integer(current_rva
      + aligned_size + virtual_padding, section_alignment_);
  }

  // Write the headers to the buffer.
  write_dos_header(reinterpret_cast<PIMAGE_DOS_HEADER>(&contents[0]));
  write_nt_header(reinterpret_cast<PIMAGE_NT_HEADERS64>(
    &contents[sizeof(IMAGE_DOS_HEADER)]),
    static_cast<std::uint32_t>(current_rva),
    static_cast<std::uint32_t>(headers_size));

  return contents;
}

// Fill in the DOS header.
inline void pe_builder::write_dos_header(PIMAGE_DOS_HEADER const dos_header) const {
  std::memset(dos_header, 0, sizeof(*dos_header));
  dos_header->e_magic  = IMAGE_DOS_SIGNATURE;
  dos_header->e_lfanew = sizeof(IMAGE_DOS_HEADER);
  // TODO: Mimic a real DOS header instead of this bare minimum code.
}

// Fill in the NT header.
inline void pe_builder::write_nt_header(PIMAGE_NT_HEADERS64 const nt_header,
    std::uint32_t const image_size, std::uint32_t const headers_size) const {
  std::memset(nt_header, 0, sizeof(*nt_header));
  nt_header->Signature                                  = IMAGE_NT_SIGNATURE;
  nt_header->FileHeader.Machine                         = IMAGE_FILE_MACHINE_AMD64;
  nt_header->FileHeader.NumberOfSections                = static_cast<std::uint16_t>(sections_.size());
  nt_header->FileHeader.SizeOfOptionalHeader            = sizeof(nt_header->OptionalHeader);
  nt_header->FileHeader.Characteristics                 = file_characteristics_;
  nt_header->OptionalHeader.Magic                       = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
  nt_header->OptionalHeader.AddressOfEntryPoint         = static_cast<std::uint32_t>(entrypoint_ - image_base_);
  nt_header->OptionalHeader.ImageBase                   = image_base_;
  nt_header->OptionalHeader.SectionAlignment            = section_alignment_;
  nt_header->OptionalHeader.FileAlignment               = file_alignment_;
  nt_header->OptionalHeader.MajorOperatingSystemVersion = 6;
  nt_header->OptionalHeader.MinorOperatingSystemVersion = 0;
  nt_header->OptionalHeader.MajorSubsystemVersion       = 6;
  nt_header->OptionalHeader.MinorSubsystemVersion       = 0;
  nt_header->OptionalHeader.Subsystem                   = subsystem_;
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

// Compute the (unaligned) headers size.
inline std::size_t pe_builder::compute_headers_size(std::size_t const num_sections) {
  // This value might get more complicated if we decide to include a proper
  // DOS header (and DOS stub).
  return sizeof(IMAGE_DOS_HEADER) +
    sizeof(IMAGE_NT_HEADERS64) +
    sizeof(IMAGE_SECTION_HEADER) * num_sections;
}

// Align an integer up to the specified alignment.
inline std::uint64_t pe_builder::align_integer(
    std::uint64_t const value, std::uint64_t const alignment) {
  auto const r = value % alignment;

  // Already aligned.
  if (r == 0)
    return value;
  
  return value + (alignment - r);
}

} // namespace pb
