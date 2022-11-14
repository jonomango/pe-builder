#include <pe-builder/pe-builder.h>
#include <cstdio>

int main() {
  pb::pe_builder pe;

  if (!pe.write("fish-frog.exe"))
    printf("Failed to write PE image.\n");
  else
    printf("Wrote PE image to file.\n");
}

