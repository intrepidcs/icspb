# Set the minimum required version of CMake
cmake_minimum_required(VERSION 3.16)

# Set the project name
project(NanopbGeneratorCpp)

# Set the C++ standard to C++17 (required for <filesystem>)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# --- Fetch nlohmann/json for JSON parsing ---
include(FetchContent)
FetchContent_Declare(
  nlohmann_json
  GIT_REPOSITORY https://github.com/nlohmann/json.git
  GIT_TAG v3.11.2 # A specific, stable version
)
FetchContent_MakeAvailable(nlohmann_json)

# Add the executable target from our source file
add_executable(nanopb_generator nanopb_generator.cpp)

# --- Statically link the C runtime library for MSVC ---
# This removes the dependency on vcruntime and ucrt DLLs, making the
# executable more portable. It's the fix for the missing ucrtbased.dll issue.
if(MSVC)
  set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

# Link the JSON library to our executable
target_link_libraries(nanopb_generator PRIVATE nlohmann_json::nlohmann_json)

if (MSVC)
target_compile_options(nanopb_generator PRIVATE /W4 /WX)
else()
target_compile_options(nanopb_generator PRIVATE -Wall -Werror)
# For GCC/Clang, we might need to link stdc++fs
find_library(STDCPPFS_LIB stdc++fs)
# C++17 <filesystem> requires linking to a specific library on some compilers.
# This command finds the appropriate library and links it.
if(STDCPPFS_LIB)
    target_link_libraries(nanopb_generator PRIVATE ${STDCPPFS_LIB})
endif()
endif()
# On older macOS, you might need to link against libc++fs
if(APPLE)
    find_library(LIBCPPFS_LIB c++fs)
    if(LIBCPPFS_LIB)
        target_link_libraries(nanopb_generator PRIVATE ${LIBCPPFS_LIB})
    endif()
endif()

# Set the output directory for the executable
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
