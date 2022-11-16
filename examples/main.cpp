#include <pe-builder/pe-builder.h>
#include <cstdio>

int main() {
  pb::pe_builder pe;

  pe.section_alignment(0x1000)
    .file_alignment(0x200)
    .image_base(0x140000000)
    .subsystem(IMAGE_SUBSYSTEM_WINDOWS_CUI)
    .file_characteristics(IMAGE_FILE_EXECUTABLE_IMAGE);

  auto& text_sec = pe.section()
    .name(".text")
    .characteristics(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_EXECUTE);
  
  text_sec.data().push_back(0xAA);
  text_sec.data().push_back(0xBB);

  auto& bss_sec = pe.section()
    .name(".bss")
    .characteristics(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE)
    .padding(0x1999);

  auto& data_sec = pe.section()
    .name(".data")
    .characteristics(IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE);

  data_sec.data().push_back(0xCC);
  data_sec.data().push_back(0xDD);

  // Set the entrypoint to the start of the .text section.
  pe.entrypoint(pe.virtual_address(text_sec));

  if (!pe.write("fish-frog.exe"))
    printf("Failed to write PE image.\n");
  else
    printf("Wrote PE image to file.\n");

  printf("VA of .text section: 0x%zX.\n", pe.virtual_address(text_sec));
  printf("VA of .bss  section: 0x%zX.\n", pe.virtual_address(bss_sec));
  printf("VA of .data section: 0x%zX.\n", pe.virtual_address(data_sec));
}

