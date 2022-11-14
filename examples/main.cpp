#include <pe-builder/pe-builder.h>
#include <cstdio>

int main() {
  pb::pe_builder pe;

  pe.section_alignment(0x1000)
    .file_alignment(0x200)
    .image_base(0x140000000)
    .entrypoint(0x140000000)
    .subsystem(IMAGE_SUBSYSTEM_WINDOWS_CUI)
    .file_characteristics(IMAGE_FILE_EXECUTABLE_IMAGE);

  if (!pe.write("fish-frog.exe"))
    printf("Failed to write PE image.\n");
  else
    printf("Wrote PE image to file.\n");
}

