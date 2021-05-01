# Specify the minimum version for CMake
cmake_minimum_required(VERSION 3.2)

# Project's name 
project(libPGC_openssl)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread -O3")

find_package(OpenSSL REQUIRED)

include_directories(${OPENSSL_INCLUDE_DIR})
  
add_executable(test_escrow_protocol test/test_escrow_protocol.cpp)

target_link_libraries(test_escrow_protocol ${OPENSSL_LIBRARIES})

add_executable(test_twisted_elgamal test/test_twisted_elgamal.cpp)

target_link_libraries(test_twisted_elgamal ${OPENSSL_LIBRARIES})

#add_executable(rust_twisted_elgamal test/rust_twisted_elgamal.cpp)

#target_link_libraries(rust_twisted_elgamal ${OPENSSL_LIBRARIES})