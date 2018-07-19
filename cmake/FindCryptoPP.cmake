find_library(Cryptopp_LIBRARY
  NAMES cryptopp
  PATHS
  /usr/lib
  /usr/local/lib)

find_path(Cryptopp_INCLUDE_DIR
  NAMES cryptopp/cryptlib.h
  PATHS
  /usr/include
  /usr/local/include)

get_filename_component(Cryptopp_LIBRARY_DIR ${Cryptopp_LIBRARY} DIRECTORY)
set(Cryptopp_LIBRARIES ${Cryptopp_LIBRARY})
set(Cryptopp_INCLUDE_DIRS ${Cryptopp_INCLUDE_DIR})
set(Cryptopp_LIBRARY_DIRS ${Cryptopp_LIBRARY_DIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(Cryptopp REQUIRED_VARS Cryptopp_LIBRARY Cryptopp_INCLUDE_DIR)
