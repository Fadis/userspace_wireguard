/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_HMAC_HPP
#define UWG_HMAC_HPP

#include <type_traits>
#include <boost/container/static_vector.hpp>
#include <crypto++/blake2.h>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  class hmac {
  public:
    template< typename Key >
    hmac( const Key &key, std::enable_if_t< is_continous_memory_container_v< Key > >* = 0 ) {
      constexpr size_t key_length = 64u;
      boost::container::static_vector< unsigned char, key_length > ipad, key_;
      if( key.size() > key_length ) {
        hasher.Update( key.data(), key.size() );
        key_.resize( key_length, 0u );
        hasher.TruncatedFinal( key_.data(), key_.size() );
      }
      else key_.insert( key_.end(), key.begin(), key.end() );
      key_.resize( key_length, 0u );
      std::transform( key_.begin(), key_.end(), std::back_inserter( ipad ), []( unsigned char v ) { return 0x36 ^ v; } );
      std::transform( key_.begin(), key_.end(), std::back_inserter( opad ), []( unsigned char v ) { return 0x5c ^ v; } );
      std::fill( key_.begin(), key_.end(), 0u );
      hasher.Update( ipad.data(), ipad.size() );
      std::fill( ipad.begin(), ipad.end(), 0u );
    }
    template< typename In >
    auto update( const In &in ) ->
      std::enable_if_t< is_continous_memory_container_v< In >, hmac& > {
      hasher.Update( in.data(), in.size() );
      return *this;
    }
    template< typename Head, typename Next, typename ...Tail >
    auto update( const Head &head, const Next &next, const Tail&... tail ) ->
      std::enable_if_t< is_continous_memory_container_v< Head >, hmac& > {
      update( head );
      update( next, tail... );
      return *this;
    }
    hmac &update( const char *begin, const char *end ) {
      hasher.Update( reinterpret_cast< const unsigned char* >( begin ), std::distance( begin, end ) );
      return *this;
    }
    template< typename Out >
    auto get( Out &out ) ->
      std::enable_if_t< is_continous_memory_container_v< Out > > {
      constexpr size_t key_length = 64u;
      boost::container::static_vector< unsigned char, key_length > key_;
      key_.resize( hasher.DigestSize(), 0u );
      hasher.Final( key_.data() );
      hasher.Update( opad.data(), opad.size() );
      std::fill( opad.begin(), opad.end(), 0u );
      hasher.Update( key_.data(), key_.size() );
      std::fill( key_.begin(), key_.end(), 0u );
      out.resize( hasher.DigestSize(), 0u );
      hasher.TruncatedFinal( out.data(), out.size() );
    }
    template< typename Head, typename Next, typename ...Tail >
    auto get( Head &head, Next &next, Tail&... tail ) ->
      std::enable_if_t< is_continous_memory_container_v< Head > > {
      get( head );
      get( next, tail... );
    }
  private:
    CryptoPP::BLAKE2s hasher;
    boost::container::static_vector< unsigned char, 64u > opad;
  };
}

#endif

