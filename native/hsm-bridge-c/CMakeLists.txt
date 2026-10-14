cmake_minimum_required(VERSION 3.25)
project(tbkeyd VERSION 4.2.0 LANGUAGES C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)

# Dependencies come from vcpkg.json in CI and from the distribution on build hosts.
find_package(OpenSSL 3.5 REQUIRED)
find_package(PkgConfig REQUIRED)
pkg_check_modules(SODIUM REQUIRED IMPORTED_TARGET libsodium)
pkg_check_modules(OQS REQUIRED IMPORTED_TARGET liboqs)
pkg_check_modules(P11KIT REQUIRED IMPORTED_TARGET p11-kit-1)

file(GLOB_RECURSE KEYD_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
list(REMOVE_ITEM KEYD_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c)

add_library(keyd_core STATIC ${KEYD_SOURCES})
target_include_directories(keyd_core PUBLIC include PRIVATE src)
target_compile_options(keyd_core PRIVATE -Wall -Wextra -Wshadow)
# The audit chain digest is fixed per release so that old segments stay verifiable.
target_compile_definitions(keyd_core PRIVATE KEYD_AUDIT_DIGEST="SHA2-384")
target_link_libraries(keyd_core PUBLIC OpenSSL::SSL OpenSSL::Crypto PkgConfig::SODIUM PkgConfig::OQS)
target_link_libraries(keyd_core PUBLIC PkgConfig::P11KIT crypt)

add_executable(tbkeyd src/main.c)
target_include_directories(tbkeyd PRIVATE src)
target_compile_options(tbkeyd PRIVATE -Wall -Wextra)
target_link_libraries(tbkeyd PRIVATE keyd_core)

install(TARGETS tbkeyd RUNTIME DESTINATION sbin)

enable_testing()
file(GLOB KEYD_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c)
add_executable(keyd_tests ${KEYD_TEST_SOURCES})
target_include_directories(keyd_tests PRIVATE src tests)
target_link_libraries(keyd_tests PRIVATE keyd_core)
add_test(NAME keyd_tests COMMAND keyd_tests)
