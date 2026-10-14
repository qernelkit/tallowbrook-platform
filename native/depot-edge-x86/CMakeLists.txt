cmake_minimum_required(VERSION 3.25)
project(edgeclip LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(edgeclip
    src/main.c
    src/cpu_features.c
    src/entropy_seed.c
    src/clip_ctr.c
    src/clip_digest.c)
target_include_directories(edgeclip PRIVATE src)
# The fast paths use AES-NI, SSE4.1, the SHA extensions and RDRAND/RDSEED.
target_compile_options(edgeclip PRIVATE -Wall -Wextra -maes -msse4.1 -msha -mrdrnd -mrdseed)
