cmake_minimum_required(VERSION 3.10)

project(PrivateCategorization VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(
    SOURCES

    aes.cpp
    hashing.cpp
    networking.cpp
    polynomials.cpp
    psi.cpp
    random.cpp
    windowing.cpp
)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -march=native")

add_executable(private_categorization main.cpp ${SOURCES})
add_executable(private_categorization_debug_entropy main.cpp ${SOURCES})
set_target_properties(private_categorization_debug_entropy PROPERTIES COMPILE_FLAGS "-DDEBUG_WITH_KEY_LEAK")
add_executable(pc_client client.cpp ${SOURCES})
add_executable(pc_server server.cpp ${SOURCES})
add_executable(benchmark benchmark.cpp ${SOURCES})

# Import Boost (for networking)
find_package(Boost REQUIRED)
include_directories(${Boost_INCLUDE_DIRS})

# Import Microsoft SEAL
find_package(SEAL 3.2.0 EXACT REQUIRED)

# Link Microsoft SEAL
target_link_libraries(private_categorization SEAL::seal)
target_link_libraries(private_categorization_debug_entropy SEAL::seal)
target_link_libraries(pc_client SEAL::seal)
target_link_libraries(pc_server SEAL::seal)
target_link_libraries(benchmark SEAL::seal)
