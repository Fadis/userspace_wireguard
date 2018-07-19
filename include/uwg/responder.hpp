/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_RESPONDER_HPP
#define UWG_RESPONDER_HPP

#include <iterator>
#include <boost/spirit/include/karma.hpp>
#include <boost/spirit/include/qi.hpp>
#include <uwg/hash.hpp>
#include <uwg/mac.hpp>
#include <uwg/kdf.hpp>
#include <uwg/dh.hpp>
#include <uwg/aead.hpp>
#include <uwg/timestamp.hpp>
#include <uwg/initial_key.hpp>
#include <uwg/clear_key.hpp>
#include <uwg/types.hpp>

namespace uwg {
  template< typename Out, typename CookieType, typename In >
  void responder_hello( key_state &key, Out &out, peer_states &peers, const wg_key_type &self_static_private, const wg_key_type &self_static_public, const wg_key_type &remote_static_public, uint32_t self_spi, const CookieType &cookie, const In &in ) {
    if( in.size() != wg_kx1_len ) throw invalid_packet();
    if( in[ 0 ] != 0x01 ) throw invalid_packet();
    auto encrypted_static = make_svv( in.data(), wg_kx1_encrypted_static_offset, wg_encrypted_static_len );
    auto encrypted_timestamp = make_svv( in.data(), wg_kx1_encrypted_tai64n_offset, wg_encrypted_tai64n_len );
    auto remote_ephemeral_public = make_svv( in.data(), wg_kx1_ephemeral_offset, wg_ephemeral_len );
    wg_key_type kdf_key;
    wg_key_type aead_key;
    wg_key_type chain_key;
    wg_key_type hash_key;
    wg_key_type incoming_remote_static_public;
    wg_key_type self_ephemeral_private;
    wg_key_type q( wg_key_len, 0u );
    wg_key_type t;
    wg_key_type empty;
    wg_key_type mac_key;
    wg_tai64n_type remote_timestamp;
    wg_key_type calculated_kx1_mac1;
    namespace qi = boost::spirit::qi;
    uint32_t remote_spi;
    qi::parse( std::next( in.begin(), wg_kx1_self_spi_offset ), std::next( in.begin(), wg_kx1_self_spi_offset + wg_spi_len ), qi::little_dword, remote_spi );
    auto kx1_mac1_message = make_svv( in.data(), 0, wg_kx1_mac1_message_len );
    auto incoming_kx1_mac1 = make_svv( in.data(), wg_kx1_mac1_offset, wg_mac_len );
    constexpr static char label_mac1[] = "mac1----";
    hash().update( label_mac1, label_mac1 + strlen( label_mac1 ) ).update( self_static_public ).get( mac_key );
    mac( mac_key ).update( kx1_mac1_message ).get( calculated_kx1_mac1 );
    if( !std::equal( calculated_kx1_mac1.begin(), calculated_kx1_mac1.end(), incoming_kx1_mac1.begin(), incoming_kx1_mac1.end() ) )
      throw invalid_packet();
    get_initial_chain_key( chain_key );
    get_initial_hash_key( hash_key, chain_key );
    kdf( chain_key ).update( remote_ephemeral_public ).get( chain_key );
    hash().update( hash_key, self_static_public ).get( hash_key );
    hash().update( hash_key, remote_ephemeral_public ).get( hash_key );
    dh( kdf_key, self_static_private, remote_ephemeral_public );
    kdf( chain_key ).update( kdf_key ).get( chain_key, aead_key );
    out.resize( wg_kx2_len, 0u );
    if( !aead_dec( incoming_remote_static_public, aead_key, 0ull, encrypted_static, hash_key ) )
      throw invalid_packet();
    hash().update( hash_key, encrypted_static ).get( hash_key );
    dh( kdf_key, self_static_private, remote_static_public );
    kdf( chain_key ).update( kdf_key ).get( chain_key, aead_key );
    if( !aead_dec( remote_timestamp, aead_key, 0ull, encrypted_timestamp, hash_key ) )
      throw invalid_packet();
    if( remote_timestamp.size() != wg_tai64n_len  )
      throw invalid_packet();
    const auto peer = peers.find( incoming_remote_static_public );
    if( peer != peers.end() ) {
      if( memcmp( peer->second.timestamp.data(), remote_timestamp.data(), wg_tai64n_len ) >= 0 )
        throw invalid_packet();
      peer->second.timestamp = remote_timestamp;
    }
    else peers.insert( std::make_pair( incoming_remote_static_public, peer_state( remote_timestamp ) ) );
    hash().update( hash_key, encrypted_timestamp ).get( hash_key );
 
 
    out.resize( wg_kx2_len, 0u );
    auto self_ephemeral_public = make_svv( out.data(), wg_kx2_ephemeral_offset, wg_ephemeral_len );
    auto encrypted_empty = make_svv( out.data(), wg_kx2_encrypted_empty_offset, wg_encrypted_empty_len );
    dh_generate( self_ephemeral_private, self_ephemeral_public );
    kdf( chain_key ).update( self_ephemeral_public ).get( chain_key );
    hash().update( hash_key, self_ephemeral_public ).get( hash_key );
    dh( kdf_key, self_ephemeral_private, remote_ephemeral_public );
    kdf( chain_key ).update( kdf_key ).get( chain_key );
    dh( kdf_key, self_ephemeral_private, remote_static_public );
    kdf( chain_key ).update( kdf_key ).get( chain_key );
    kdf( chain_key ).update( q ).get( chain_key, t, aead_key );
    hash().update( hash_key, t ).get( hash_key );
    aead_enc( encrypted_empty, aead_key, 0ull, empty, hash_key );
    hash().update( hash_key, encrypted_empty ).get( hash_key );
    out[ 0 ] = 0x02;
    namespace karma = boost::spirit::karma;
    karma::generate( std::next( out.begin(), wg_kx2_self_spi_offset ), karma::little_dword, self_spi );
    karma::generate( std::next( out.begin(), wg_kx2_remote_spi_offset ), karma::little_dword, remote_spi );
    auto kx2_mac1_message = make_svv( out.data(), 0, wg_kx2_mac1_message_len );
    auto kx2_mac1 = make_svv( out.data(), wg_kx2_mac1_offset, wg_mac_len );
    hash().update( label_mac1, label_mac1 + strlen( label_mac1 ) ).update( remote_static_public ).get( mac_key );
    mac( mac_key ).update( kx2_mac1_message ).get( kx2_mac1 );
    if( !cookie.empty() ) {
      auto mac2_message = make_svv( out.data(), 0, wg_kx2_mac2_message_len );
      auto mac2 = make_svv( out.data(), wg_kx2_mac2_offset, wg_mac_len );
      mac( cookie ).update( mac2_message ).get( mac2 );
    }
    kdf( chain_key ).update( empty ).get( key.receive_key, key.send_key );
    kdf_key.resize( wg_key_len );
    clear_key( kdf_key );
    clear_key( aead_key );
    clear_key( mac_key );
    clear_key( q );
    clear_key( t );
    clear_key( self_ephemeral_private );
    clear_key( chain_key );
    clear_key( hash_key );
  }
}
#endif
