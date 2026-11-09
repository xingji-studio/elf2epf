cmake_minimum_required(VERSION 3.16)
project(elf2epf VERSION 0.1.0 LANGUAGES CXX)

add_library(elf2epf_core
    src/elf.cpp
    src/converter.cpp
    src/epf.cpp
    src/io.cpp)
target_include_directories(elf2epf_core PUBLIC include PRIVATE src)
target_compile_features(elf2epf_core PUBLIC cxx_std_17)
set_target_properties(elf2epf_core PROPERTIES CXX_EXTENSIONS OFF)
if(MSVC)
    target_compile_options(elf2epf_core PRIVATE /W4 /permissive- /utf-8)
else()
    target_compile_options(elf2epf_core PRIVATE -Wall -Wextra -Wpedantic -Wconversion -Wshadow)
endif()

add_executable(elf2epf src/main.cpp)
target_link_libraries(elf2epf PRIVATE elf2epf_core)
if(MINGW)
    target_link_options(elf2epf PRIVATE -municode)
endif()
if(MSVC)
    target_compile_options(elf2epf PRIVATE /utf-8)
endif()
install(TARGETS elf2epf RUNTIME DESTINATION bin)

include(CTest)
if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter)
    find_program(EPF_TEST_CC NAMES cc gcc clang)
    find_program(EPF_TEST_LD NAMES ld)
    if(Python3_FOUND AND EPF_TEST_CC AND EPF_TEST_LD AND UNIX AND NOT APPLE)
        add_test(NAME integration COMMAND "${Python3_EXECUTABLE}"
            "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.py"
            --tool $<TARGET_FILE:elf2epf> --cc "${EPF_TEST_CC}" --ld "${EPF_TEST_LD}")
        set_tests_properties(integration PROPERTIES TIMEOUT 120)
    endif()
endif()
