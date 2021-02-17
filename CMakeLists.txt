cmake_minimum_required(VERSION 3.15)
project(replicat LANGUAGES CXX)
find_package(Python COMPONENTS Interpreter Development REQUIRED)
find_package(pybind11 CONFIG REQUIRED)

SET(CMAKE_CXX_STANDARD 17)
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fstrict-aliasing -Wall -mpclmul -msse2 -msse4.1 -O2")
pybind11_add_module(_replicat_adapters "src/adapters.cpp")
