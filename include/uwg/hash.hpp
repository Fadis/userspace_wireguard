/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_HASH_HPP
#define UWG_HASH_HPP

#include <type_traits>
#include <crypto++/blake2.h>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  class hash {
  public:
    hash() {}
    template< typename In >
    auto update( const In &in ) ->
      std::enable_if_t< is_continous_memory_container_v< In >, hash& > {
      hasher.Update( in.data(), in.size() );
      return *this;
    }
    template< typename Head, typename Next, typename ...Tail >
    auto update( const Head &head, const Next &next, const Tail&... tail ) ->
      std::enable_if_t< is_continous_memory_container_v< Head >, hash& > {
      update( head );
      update( next, tail... );
      return *this;
    }
    hash &update( const char *begin, const char *end ) {
      hasher.Update( reinterpret_cast< const unsigned char* >( begin ), std::distance( begin, end ) );
      return *this;
    }
    template< typename Out >
    auto get( Out &out ) ->
      std::enable_if_t< is_continous_memory_container_v< Out > > {
      out.resize( 32u );
      hasher.TruncatedFinal( out.data(), out.size() );
    }
  private:
    CryptoPP::BLAKE2s hasher;
  };
}

#endif

