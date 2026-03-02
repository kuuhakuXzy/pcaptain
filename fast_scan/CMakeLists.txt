cmake_minimum_required(VERSION 3.12)
project(fast_scan VERSION 1.0 LANGUAGES CXX)

# Require C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Find libpcap
find_package(PkgConfig REQUIRED)
pkg_check_modules(PCAP REQUIRED libpcap)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/lib)
include_directories(${PCAP_INCLUDE_DIRS})

# Source files
set(SOURCES
    fast_scan.cpp
    src/scanner.cpp
    src/inference.cpp
)

# Create executable
add_executable(fastscan ${SOURCES})

# Link libraries
target_link_libraries(fastscan ${PCAP_LIBRARIES})

# Compiler flags
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(fastscan PRIVATE -O3 -Wall -Wextra)
endif()

if(MSVC)
    target_compile_options(fastscan PRIVATE /O2 /W4)
endif()

# Install target
install(TARGETS fastscan DESTINATION bin)
