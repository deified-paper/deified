find_package(LLVM REQUIRED CONFIG)

message(STATUS "Building plugin for LLVM (${LLVM_PACKAGE_VERSION}): ${LLVM_DIR}")

add_definitions(${LLVM_DEFINITIONS})
include_directories(${LLVM_INCLUDE_DIRS})

if (NOT LLVM_ENABLE_EH)
  string(APPEND CMAKE_CXX_FLAGS " -fno-exceptions")
endif()

if (NOT LLVM_ENABLE_RTTI)
  string(APPEND CMAKE_CXX_FLAGS " -fno-rtti")
endif()

# Mark nodelete to work around unload bug
if (LLVM_MAJOR_VERSION LESS_EQUAL 5)
  string(APPEND CMAKE_CXX_FLAGS " -Wl,-znodelete")
endif()

add_library(utils SHARED
  hq-syscall.cpp
  utils.cpp
)

add_library(cfi MODULE
  cfi-instrument.cpp
  cfi-finalize.cpp
  cfi-init.cpp
)

target_link_libraries(cfi PRIVATE utils)
llvm_config(cfi USE_SHARED analysis core demangle passes support)

add_library(dfi MODULE
  dfi-init.cpp
  dfi-instrument.cpp
)

target_link_libraries(dfi PRIVATE utils)
llvm_config(dfi USE_SHARED analysis core demangle passes support)

add_library(hq MODULE
  hq-init.cpp
)

target_link_libraries(hq PRIVATE utils)
llvm_config(hq USE_SHARED analysis core demangle passes support)
