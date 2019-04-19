cmake_minimum_required(VERSION 3.10)

project(PrivateCategorization VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

add_executable(private_categorization main.cpp)

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Link Microsoft SEAL
target_link_libraries(private_categorization SEAL::seal)
