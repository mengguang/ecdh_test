cmake_minimum_required(VERSION 3.15)
project(ecdh_test C)

set(CMAKE_C_STANDARD 99)

add_executable(ecdh_test main.c curve-specific.inc platform-specific.inc types.h uECC.c uECC.h uECC_vli.h)