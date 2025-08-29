cmake_minimum_required(VERSION 3.15)
project(KittyLoader VERSION 1.0.0 LANGUAGES CXX ASM_MASM)

set(PROJECT_DESCRIPTION "Ultimate Evasive Loader for Red Team Operations")
set(PROJECT_URL "https://github.com/tlsbollei/KittyLoader")

option(BUILD_TESTS "Build test applications" OFF)
option(BUILD_EXAMPLES "Build example applications" OFF)

cmake_policy(SET CMP0076 NEW)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
    add_compile_options(/W4 /WX /O2 /MT /MP)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Werror -O3 -fvisibility=hidden)
    if(MINGW)
        add_compile_options(-static -static-libgcc -static-libstdc++)
    endif()
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

include_directories(${CMAKE_SOURCE_DIR}/include)

file(GLOB SOURCE_FILES 
    "src/*.cpp"
    "src/*.asm"
)

add_library(KittyLoader SHARED ${SOURCE_FILES})

if(MSVC)
    set_source_files_properties(src/entry_hijack.asm PROPERTIES LANGUAGE MASM)
else()
    # Cross-compilation setup for MinGW
    set(CMAKE_ASM_MASM_COMPILER "ml64")
    set(CMAKE_ASM_MASM_FLAGS "/c /Fo")
endif()

target_link_libraries(KittyLoader
    psapi
    advapi32
    bcrypt
)

set_target_properties(KittyLoader PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "KittyLoader"
    ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin
)

install(TARGETS KittyLoader
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    INCLUDES DESTINATION include
)

install(DIRECTORY include/ DESTINATION include)

if(BUILD_TESTS)
    add_executable(test_loader tests/test_loader.cpp)
    target_link_libraries(test_loader KittyLoader)
    install(TARGETS test_loader DESTINATION bin)
endif()

include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/KittyLoaderConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/cmake/KittyLoaderConfig.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/KittyLoaderConfig.cmake
    INSTALL_DESTINATION lib/cmake/KittyLoader
)

install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/KittyLoaderConfig.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/KittyLoaderConfigVersion.cmake
    DESTINATION lib/cmake/KittyLoader
)

export(EXPORT KittyLoaderTargets
    FILE ${CMAKE_CURRENT_BINARY_DIR}/KittyLoaderTargets.cmake
)

set(CPACK_PACKAGE_NAME "KittyLoader")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_DESCRIPTION ${PROJECT_DESCRIPTION})
set(CPACK_PACKAGE_URL ${PROJECT_URL})
set(CPACK_PACKAGE_VENDOR "KittyLoader Team")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
include(CPack)