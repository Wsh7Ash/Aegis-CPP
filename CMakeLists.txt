cmake_minimum_required(VERSION 3.10)
project(AegisCPP VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

# Header-only library, main demo executable
add_executable(AegisCPP src/main.cpp)
