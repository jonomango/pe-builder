cmake_minimum_required(VERSION 3.9)

project(pe-builder
  DESCRIPTION ""
  HOMEPAGE_URL "https://github.com/jonomango/pe-builder"
  LANGUAGES CXX C
)

option(PE_BUILDER_BUILD_EXAMPLES "Build the pe-builder examples." OFF)

# create pe_builder as an INTERFACE since it is header-only
add_library(pe-builder INTERFACE)
target_include_directories(pe-builder INTERFACE include)
target_compile_features(pe-builder INTERFACE cxx_std_17 c_std_11)

# hack to get files to show up in IDEs as a project
add_custom_target(pe-builder-library SOURCES include/pe-builder/pe-builder.h)

# build the examples
if (PE_BUILDER_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()