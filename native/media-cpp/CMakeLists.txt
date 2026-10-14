cmake_minimum_required(VERSION 3.25)
project(vaultarc VERSION 2.6.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(BOTAN REQUIRED IMPORTED_TARGET botan-3)
pkg_check_modules(CRYPTOPP REQUIRED IMPORTED_TARGET libcrypto++)

file(GLOB_RECURSE VAULTARC_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.cpp)
list(REMOVE_ITEM VAULTARC_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp)

add_library(vaultarc_core STATIC ${VAULTARC_SOURCES})
target_include_directories(vaultarc_core PUBLIC src)
target_compile_options(vaultarc_core PRIVATE -Wall -Wextra)
# Chunk index digest, fixed per release so a dedupe store stays consistent across upgrades.
target_compile_definitions(vaultarc_core PRIVATE VAULTARC_CHUNK_HASH="SHA-512")
target_link_libraries(vaultarc_core PUBLIC PkgConfig::BOTAN PkgConfig::CRYPTOPP)

add_executable(vaultarc src/main.cpp)
target_link_libraries(vaultarc PRIVATE vaultarc_core)

enable_testing()
file(GLOB VAULTARC_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)
add_executable(vaultarc_tests ${VAULTARC_TEST_SOURCES})
target_include_directories(vaultarc_tests PRIVATE src tests)
target_link_libraries(vaultarc_tests PRIVATE vaultarc_core)
add_test(NAME vaultarc_tests COMMAND vaultarc_tests)
