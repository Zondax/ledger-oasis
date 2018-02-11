#*******************************************************************************
#*   (c) 2018 ZondaX GmbH
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

set(CMAKE_CXX_STANDARD 11)
add_subdirectory(cmake/gtest)

string(APPEND CMAKE_CXX_FLAGS_DEBUG " -fsanitize=address -fno-omit-frame-pointer")
string(APPEND CMAKE_LINKER_FLAGS_DEBUG " -fsanitize=address -fno-omit-frame-pointer")

##############################################################
##############################################################
##############################################################
##############################################################
file(GLOB_RECURSE JSMN_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/deps/jsmn/src/jsmn.c
        )

file(GLOB_RECURSE TINYCBOR_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/deps/tinycbor/src/cborparser.c
        )

file(GLOB_RECURSE LIB_SRC
        src/ledger/deps/ledger-zxlib/src/hexutils.c
        src/ledger/deps/ledger-zxlib/src/zxmacros.c
        #########
        src/ledger/src/lib/parser.c
        src/ledger/src/lib/parser_impl.c

#        src/ledger/src/lib/json/json_parser.c
#        src/ledger/src/lib/json/tx_parser.c
#        src/ledger/src/lib/json/tx_display.c
#        src/ledger/src/lib/json/tx_validate.c
        )

file(GLOB_RECURSE TESTS_SRC
        ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp)


add_library(cbor_parser STATIC ${LIB_SRC} ${TINYCBOR_SRC})
target_include_directories(cbor_parser PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/deps/tinycbor/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/src/lib
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/deps/ledger-zxlib/include
        )

set(JSON_BuildTests OFF CACHE INTERNAL "")
add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/deps/json)

add_executable(unittests ${TESTS_SRC})
target_include_directories(unittests PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/deps/tinycbor/src
        ${CMAKE_CURRENT_SOURCE_DIR}/src/ledger/deps/ledger-zxlib/hexutils.c
        ${gtest_SOURCE_DIR}/include
        ${gmock_SOURCE_DIR}/include
        )
target_link_libraries(unittests gtest_main cbor_parser nlohmann_json::nlohmann_json)
add_test(unittests ${PROJECT_BINARY_DIR}/unittests)

###############################################################
# Force tests to depend from app compiling
###############################################################

#set(DISABLE_DOCKER_BUILDS OFF CACHE BOOL "Disables Docker Builds")
#
#if (NOT DISABLE_DOCKER_BUILDS)
#    add_custom_target(ledger_app
#            COMMAND make build
#            WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
#            )
#    add_dependencies(unittests ledger_app)
#endif()
