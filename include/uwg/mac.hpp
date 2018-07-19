/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_MAC_HPP
#define UWG_MAC_HPP

#include <type_traits>
#include <crypto++/blake2.h>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  class mac {
  public:
    template< typename Key >
    mac( const Key &key, std::enable_if_t< is_continous_memory_container_v< Key > >* = 0 ) :
      hasher( key.data(), key.size(), nullptr, 0, nullptr, 0, false, 16u ) {
      //hasher.Update( key.data(), key.size() );
    }
    template< typename In >
    auto update( const In &in ) ->
      std::enable_if_t< is_continous_memory_container_v< In >, mac& > {
      hasher.Update( in.data(), in.size() );
      return *this;
    }
    template< typename Head, typename Next, typename ...Tail >
    auto update( const Head &head, const Next &next, const Tail&... tail ) ->
      std::enable_if_t< is_continous_memory_container_v< Head >, mac& > {
      update( head );
      update( next, tail... );
      return *this;
    }
    mac &update( const char *begin, const char *end ) {
      hasher.Update( reinterpret_cast< const unsigned char* >( begin ), std::distance( begin, end ) );
      return *this;
    }
    template< typename Out >
    auto get( Out &out ) ->
      std::enable_if_t< is_continous_memory_container_v< Out > > {
      out.resize( 16u );
      hasher.TruncatedFinal( out.data(), out.size() );
    }
  private:
    CryptoPP::BLAKE2s hasher;
  };
}

#endif

