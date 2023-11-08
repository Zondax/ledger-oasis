#*******************************************************************************
#*   (c) 2018-2021 Zondax GmbH
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************
cmake_minimum_required(VERSION 3.0)
project(ledger-oasis VERSION 0.0.0)
enable_testing()

cmake_policy(SET CMP0025 NEW)
set(CMAKE_CXX_STANDARD 11)

option(ENABLE_FUZZING "Build with fuzzing instrumentation and build fuzz targets" OFF)
option(ENABLE_COVERAGE "Build with source code coverage instrumentation" OFF)
option(ENABLE_SANITIZERS "Build with ASAN and UBSAN" ON)

string(APPEND CMAKE_C_FLAGS " -fno-omit-frame-pointer -g")
string(APPEND CMAKE_CXX_FLAGS " -fno-omit-frame-pointer -g")
string(APPEND CMAKE_LINKER_FLAGS " -fno-omit-frame-pointer -g")

add_definitions(-DAPP_STANDARD)

if(ENABLE_FUZZING)
    add_definitions(-DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION=1)
    SET(ENABLE_SANITIZERS ON CACHE BOOL "Sanitizer automatically enabled" FORCE)
    SET(CMAKE_BUILD_TYPE Debug)

    if (DEFINED ENV{FUZZ_LOGGING})
        add_definitions(-DFUZZING_LOGGING)
        message(FATAL_ERROR "Fuzz logging enabled")
    endif()

    set(CMAKE_CXX_CLANG_TIDY clang-tidy -checks=-*,bugprone-*,cert-*,clang-analyzer-*,-cert-err58-cpp,misc-*,-bugprone-suspicious-include)

    if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        # require at least clang 3.2
        if (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 10.0)
            message(FATAL_ERROR "Clang version must be at least 10.0!")
        endif()
    else()
        message(FATAL_ERROR
                "You are using an unsupported compiler! Fuzzing only works with Clang 10.\n"
                "1. Install clang-10 \n"
                "2. Pass -DCMAKE_C_COMPILER=clang-10 -DCMAKE_CXX_COMPILER=clang++-10")
    endif()

    string(APPEND CMAKE_C_FLAGS " -fsanitize=fuzzer-no-link")
    string(APPEND CMAKE_CXX_FLAGS " -fsanitize=fuzzer-no-link")
    string(APPEND CMAKE_LINKER_FLAGS " -fsanitize=fuzzer-no-link")
endif()

if(ENABLE_COVERAGE)
    string(APPEND CMAKE_C_FLAGS " -fprofile-instr-generate -fcoverage-mapping")
    string(APPEND CMAKE_CXX_FLAGS " -fprofile-instr-generate -fcoverage-mapping")
    string(APPEND CMAKE_LINKER_FLAGS " -fprofile-instr-generate -fcoverage-mapping")
endif()

if(ENABLE_SANITIZERS)
    string(APPEND CMAKE_C_FLAGS " -fsanitize=address,undefined -fsanitize-recover=address,undefined")
    string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address,undefined -fsanitize-recover=address,undefined")
    string(APPEND CMAKE_LINKER_FLAGS " -fsanitize=address,undefined -fsanitize-recover=address,undefined")
endif()

include(cmake/conan/CMakeLists.txt)
add_subdirectory(cmake/gtest)

string(APPEND CMAKE_CXX_FLAGS " -fsanitize=address -fno-omit-frame-pointer")
string(APPEND CMAKE_LINKER_FLAGS " -fsanitize=address -fno-omit-frame-pointer")

##############################################################
##############################################################
#  static libs
file(GLOB_RECURSE TINYCBOR_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src/cborparser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src/cborvalidation.c
        )

file(GLOB_RECURSE LIB_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/*.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/sha512/sha512.c
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/picohash/
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/consumer/parser_consumer.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/consumer/parser_impl_con.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser_impl_eth.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/eth_utils.c
        )

file(GLOB_RECURSE LIB_VAL_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/src/*.c
        #########
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/parser.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/validator/parser_validator.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/validator/parser_impl_val.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/validator/vote_fsm.c
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/validator/vote.c
        )

add_library(app_lib STATIC
        ${LIB_SRC}
        ${TINYCBOR_SRC}
        )
add_library(app_val_lib STATIC
        ${LIB_VAL_SRC}
        )

target_compile_definitions(app_lib PRIVATE APP_CONSUMER)
target_compile_definitions(app_lib PRIVATE NO_DISPLAY)
target_compile_definitions(app_val_lib PRIVATE APP_VALIDATOR)

target_include_directories(app_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/app/ui
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/sha512
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/picohash/
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/consumer
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        )

target_include_directories(app_val_lib PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/app/ui
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/sha512
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/validator
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        )

##############################################################
##############################################################
#  Tests
file(GLOB_RECURSE TESTS_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp/*.cpp
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/utils/*.cpp
        )

file(GLOB_RECURSE TESTS_VAL_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/cpp_val/*.cpp
        )

add_executable(unittests ${TESTS_SRC})
target_compile_definitions(unittests PRIVATE APP_CONSUMER=1)
add_executable(unittests_val ${TESTS_VAL_SRC})
target_compile_definitions(unittests_val PRIVATE APP_VALIDATOR=1)

target_include_directories(unittests PUBLIC
        ${gtest_SOURCE_DIR}/include
        ${gmock_SOURCE_DIR}/include
        ${CONAN_INCLUDE_DIRS_FMT}
        ${CONAN_INCLUDE_DIRS_JSONCPP}
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycbor/src
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/utils
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/app/ui
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/picohash/
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        )

target_include_directories(unittests_val PUBLIC
        ${gtest_SOURCE_DIR}/include
        ${gmock_SOURCE_DIR}/include
        ${CONAN_INCLUDE_DIRS_FMT}
        ${CONAN_INCLUDE_DIRS_JSONCPP}
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/app/ui
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ledger-zxlib/include
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/common
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src/validator
        ${CMAKE_CURRENT_SOURCE_DIR}/app/src
        )

add_compile_definitions(TESTVECTORS_DIR="${CMAKE_CURRENT_SOURCE_DIR}/tests/")

target_link_libraries(unittests PRIVATE
        gtest_main
        app_lib
        CONAN_PKG::fmt
        CONAN_PKG::jsoncpp)

target_link_libraries(unittests_val PRIVATE
        gtest_main
        app_val_lib
        CONAN_PKG::fmt
        CONAN_PKG::jsoncpp)

add_test(unittests ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unittests)
add_test(unittests_val ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/unittests_val)

set_tests_properties(unittests PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)
set_tests_properties(unittests_val PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/tests)


##############################################################
##############################################################
#  Fuzz Targets
if(ENABLE_FUZZING)
    set(FUZZ_TARGETS
        parser_parse
        )

    foreach(target ${FUZZ_TARGETS})
        add_executable(fuzz-${target} ${CMAKE_CURRENT_SOURCE_DIR}/fuzz/${target}.cpp)
        target_include_directories(fuzz-${target} PUBLIC deps/PicoSHA2)
        target_link_libraries(fuzz-${target} PRIVATE app_lib)
        target_link_options(fuzz-${target} PRIVATE "-fsanitize=fuzzer")
        target_compile_definitions(fuzz-${target} PRIVATE APP_CONSUMER)
    endforeach()
endif()
