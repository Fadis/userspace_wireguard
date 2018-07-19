/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_KDF_HPP
#define UWG_KDF_HPP

#include <type_traits>
#include <boost/container/static_vector.hpp>
#include <uwg/static_vector_view.hpp>
#include <uwg/hmac.hpp>

namespace uwg {
  class kdf {
  public:
    template< typename Key >
    kdf( const Key &key, std::enable_if_t< is_continous_memory_container_v< Key > >* = 0 ) : hmac_( key ), step{ 0u } {}
    template< typename In >
    auto update( const In &in ) ->
      std::enable_if_t< is_continous_memory_container_v< In >, kdf& > {
      hmac_.update( in );
      step[ 0 ] = 0u;
      return *this;
    }
    template< typename Head, typename Next, typename ...Tail >
    auto update( const Head &head, const Next &next, const Tail&... tail ) ->
      std::enable_if_t< is_continous_memory_container_v< Head >, kdf& > {
      update( head );
      update( next, tail... );
      return *this;
    }
    kdf &update( const char *begin, const char *end ) {
      hmac_.update( begin, end );
      step[ 0 ] = 0u;
      return *this;
    }
    template< typename Out >
    auto get( Out &out ) ->
      std::enable_if_t< is_continous_memory_container_v< Out >, kdf& > {
      if( step[ 0 ] == 0u ) {
        hmac_.get( initial_key );
        ++step[ 0 ];
        hmac gen_cur( initial_key );
        gen_cur.update( step );
        gen_cur.get( prev );
        out.clear();
        out.insert( out.begin(), prev.begin(), prev.end() );
      }
      else {
        ++step[ 0 ];
        hmac gen_cur( initial_key );
        gen_cur.update( prev );
        gen_cur.update( step );
        gen_cur.get( prev );
        out.clear();
        out.insert( out.begin(), prev.begin(), prev.end() );
      }
      return *this;
    }
    template< typename Head, typename Next, typename ...Tail >
    auto get( Head &head, Next &next, Tail&... tail ) ->
      std::enable_if_t< is_continous_memory_container_v< Head >, kdf& > {
      get( head );
      get( next, tail... );
      return *this;
    }
  private:
    hmac hmac_;
    boost::container::static_vector< unsigned char, 32u > initial_key;
    boost::container::static_vector< unsigned char, 32u > prev;
    boost::container::static_vector< unsigned char, 1u > step;
  };
}

#endif
