add_executable( uwg uwg.cpp )
target_link_libraries( uwg ${Boost_LIBRARIES} ${LIBSODIUM_LIBRARIES} ${Cryptopp_LIBRARIES} Threads::Threads )
