cmake_minimum_required(VERSION 3.17)
project(flyingsocks-router C)
set(PROJECT_VERSION "3.0")
set(PROJECT_DESCRIPTION "flyingsocks client in ARM Linux router")

set(CMAKE_C_STANDARD 99)

if (CMAKE_BUILD_TYPE MATCHES Debug)
    set(EXECUTABLE_FILE_NAME fscli-debug)
else()
    set(EXECUTABLE_FILE_NAME fscli)
endif()

set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/bin)

set(LIB_PATHS "/usr/lib64 /usr/lib /usr/local/lib /usr/local/lib64")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a" ".so")

aux_source_directory(${PROJECT_SOURCE_DIR}/src SEC_LIST)

find_library(LIB_SSL NAMES ssl PATHS ${LIB_PATHS})
find_library(LIB_CRYPTO NAMES crypto PATHS ${LIB_PATHS})
message(STATUS ssl library:${LIB_SSL}${LIB_CRYPTO})
find_library(LIB_CONFUSE NAMES confuse PATHS ${LIB_PATHS})
message(STATUS confuse library:${LIB_CONFUSE})
find_library(LIB_EVENT_CORE NAMES event_core PATHS ${LIB_PATHS})
message(STATUS event_core library:${LIB_EVENT_CORE})
find_library(LIB_EVENT_SSL NAMES event_openssl PATHS ${LIB_PATHS})
message(STATUS event_ssl library:${LIB_EVENT_SSL})
find_library(LIB_EVENT_EXTRA NAMES event_extra PATHS ${LIB_PATHS})
message(STATUS event_extra library:${LIB_EVENT_EXTRA})

if (CMAKE_BUILD_TYPE MATCHES Debug)
    add_definitions(-DDEBUG)
endif()

add_executable(${EXECUTABLE_FILE_NAME} ${SEC_LIST})
target_link_libraries(${EXECUTABLE_FILE_NAME} ${LIB_SSL} ${LIB_CRYPTO} ${LIB_CONFUSE} ${LIB_EVENT_CORE} ${LIB_EVENT_SSL} ${LIB_EVENT_EXTRA} ${LIB_EVENT_PTHREAD})

install(TARGETS ${EXECUTABLE_FILE_NAME} DESTINATION bin)