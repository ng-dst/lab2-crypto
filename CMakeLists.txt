cmake_minimum_required(VERSION 3.17)
project(crypt2)

set(CMAKE_CXX_STANDARD 20)

add_executable(crypt2 main.cpp src/cipher.cpp src/solve.cpp)
target_link_libraries(crypt2 ${CMAKE_SOURCE_DIR}/lib/libcm.so)