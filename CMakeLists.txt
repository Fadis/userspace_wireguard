cmake_minimum_required(VERSION 2.8)
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/")
PROJECT(userspace_wireguard)
INCLUDE (CheckIncludeFiles)
include (FindPkgConfig)
include(CheckCXXSourceCompiles)

# build type
#set(CMAKE_BUILD_TYPE Debug)

# compile option (Debug) 
set(CMAKE_CXX_FLAGS_DEBUG "-std=c++17 -g -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "-std=c++17 -g -Wall -Wextra -Werror")

# compile option (Release)
set(CMAKE_CXX_FLAGS_RELEASE "-march=native -std=c++17 -W -Wall -Wextra -Werror -O3")
set(CMAKE_C_FLAGS_RELEASE "-march=native -std=c++17 -W -Wall -Wextra -Werror -O3")

#if you don't want the full compiler output, remove the following line
set(CMAKE_VERBOSE_MAKEFILE OFF)

find_package(Threads REQUIRED)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.49.0 COMPONENTS program_options system REQUIRED )
pkg_check_modules( LIBSODIUM REQUIRED libsodium )
find_package(CryptoPP REQUIRED)

INCLUDE_DIRECTORIES( ${CMAKE_CURRENT_SOURCE_DIR}/include
  ${CMAKE_CURRENT_BINARY_DIR}/include ${Boost_INCLUDE_DIRS}
  ${LIBSODIUM_INCLUDE_DIRS} ${Cryptopp_INCLUDE_DIRS} )
link_directories( ${Boost_LIBRARY_DIRS} ${LIBSODIUM_LIBRARY_DIRS} ${Cryptpp_LIBRARY_DIRS} )
subdirs( include src )

