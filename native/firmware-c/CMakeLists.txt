cmake_minimum_required(VERSION 3.25)
project(gwfw VERSION 3.4.0 LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# mbedTLS from the distribution (conanfile.txt declares it for the device build).
find_library(MBEDTLS_LIB mbedtls REQUIRED)
find_library(MBEDX509_LIB mbedx509 REQUIRED)
find_library(MBEDCRYPTO_LIB mbedcrypto REQUIRED)

# Stage-1 loader: no libc crypto, built as a host library so the unit tests can drive it.
add_library(gw_boot STATIC
    boot/stage1_sha256.c
    boot/stage1_aes.c
    boot/stage1_main.c)
target_include_directories(gw_boot PUBLIC include boot)
target_compile_options(gw_boot PRIVATE -Wall -Wextra -ffreestanding)

file(GLOB_RECURSE GW_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c)
list(REMOVE_ITEM GW_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/src/main.c)

add_library(gw_core STATIC ${GW_SOURCES})
target_include_directories(gw_core PUBLIC include PRIVATE src)
target_compile_options(gw_core PRIVATE -Wall -Wextra)
target_link_libraries(gw_core PUBLIC ${MBEDTLS_LIB} ${MBEDX509_LIB} ${MBEDCRYPTO_LIB} gw_boot)

add_executable(gwfw src/main.c)
target_include_directories(gwfw PRIVATE src)
target_link_libraries(gwfw PRIVATE gw_core)

enable_testing()
file(GLOB GW_TEST_SOURCES CONFIGURE_DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c)
add_executable(gw_tests ${GW_TEST_SOURCES})
target_include_directories(gw_tests PRIVATE src include tests)
target_link_libraries(gw_tests PRIVATE gw_core)
add_test(NAME gw_tests COMMAND gw_tests)
