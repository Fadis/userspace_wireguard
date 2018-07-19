/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_COOKIE_HPP
#define UWG_COOKIE_HPP
#include <iterator>
#include <boost/spirit/include/karma.hpp>
#include <boost/spirit/include/qi.hpp>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <uwg/hash.hpp>
#include <uwg/mac.hpp>
#include <uwg/kdf.hpp>
#include <uwg/dh.hpp>
#include <uwg/xaead.hpp>
#include <uwg/timestamp.hpp>
#include <uwg/initial_key.hpp>
#include <uwg/clear_key.hpp>
#include <uwg/types.hpp>
#include <uwg/dump.hpp>
namespace uwg {
  template< typename Out >
  void generate_cookie_key( Out &out ) {
    out.resize( wg_key_len );
    randombytes_buf( out.data(), out.size() );
  }
  template< typename In >
  void parse_cookie( wg_key_type &cookie, const wg_key_type &self_static_public, const wg_key_type &mac1, const In &in ) {
    if( in.size() != wg_cookie_len ) throw invalid_packet();
    if( in[ 0 ] != 0x03 ) throw invalid_packet();
    constexpr static char label_mac1[] = "cookie--";
    wg_key_type aead_key;
    hash().update( label_mac1, label_mac1 + strlen( label_mac1 ) ).update( self_static_public ).get( aead_key );
    auto incoming_nonce = make_svv( in.data(), wg_cookie_nonce_offset, wg_nonce_len );
    auto encrypted_cookie = make_svv( in.data(), wg_cookie_cookie_offset, wg_cookie_len );
    if( !xaead_dec( cookie, aead_key, incoming_nonce, encrypted_cookie, mac1 ) )
      throw invalid_packet();
  }

}

#endif

