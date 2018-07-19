/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_INITIATOR_HPP
#define UWG_INITIATOR_HPP
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
#include <uwg/dump.hpp>
namespace uwg {
  template< typename Out, typename CookieType >
  void initiator_hello_phase1( kx_state &stat, Out &out, const wg_key_type &self_static_private, const wg_key_type &self_static_public, const wg_key_type &remote_static_public, uint32_t self_spi, const CookieType &cookie ) {
    wg_key_type kdf_key;
    wg_key_type aead_key;
    wg_key_type mac_key;
    wg_tai64n_type self_timestamp;
    dh_generate( stat.self_ephemeral_private, stat.self_ephemeral_public );
    get_initial_chain_key( stat.chain_key );
    get_initial_hash_key( stat.hash_key, stat.chain_key );
    kdf( stat.chain_key ).update( stat.self_ephemeral_public ).get( stat.chain_key );
    hash().update( stat.hash_key, remote_static_public ).get( stat.hash_key );
    hash().update( stat.hash_key, stat.self_ephemeral_public ).get( stat.hash_key );
    dh( kdf_key, stat.self_ephemeral_private, remote_static_public );
    kdf( stat.chain_key ).update( kdf_key ).get( stat.chain_key, aead_key );
    out.resize( wg_kx1_len, 0u );
    auto encrypted_static = make_svv( out.data(), wg_kx1_encrypted_static_offset, wg_encrypted_static_len );
    aead_enc( encrypted_static, aead_key, 0ull, self_static_public, stat.hash_key );
    hash().update( stat.hash_key, encrypted_static ).get( stat.hash_key );
    dh( kdf_key, self_static_private, remote_static_public );
    kdf( stat.chain_key ).update( kdf_key ).get( stat.chain_key, aead_key );
    timestamp( std::back_inserter( self_timestamp ) );
    auto encrypted_timestamp = make_svv( out.data(), wg_kx1_encrypted_tai64n_offset, wg_encrypted_tai64n_len );
    aead_enc( encrypted_timestamp, aead_key, 0ull, self_timestamp, stat.hash_key );
    hash().update( stat.hash_key, encrypted_timestamp ).get( stat.hash_key );
    out[ 0 ] = 0x01;
    namespace karma = boost::spirit::karma;
    karma::generate( std::next( out.begin(), wg_kx1_self_spi_offset ), karma::little_dword, self_spi );
    std::copy( stat.self_ephemeral_public.begin(), stat.self_ephemeral_public.end(), std::next( out.begin(), wg_kx1_ephemeral_offset ) );
    constexpr static char label_mac1[] = "mac1----";
    auto mac1_message = make_svv( out.data(), 0, wg_kx1_mac1_message_len );
    auto mac1 = make_svv( out.data(), wg_kx1_mac1_offset, wg_mac_len );
    hash().update( label_mac1, label_mac1 + strlen( label_mac1 ) ).update( remote_static_public ).get( mac_key );
    mac( mac_key ).update( mac1_message ).get( mac1 );
    stat.mac1.resize( mac1.size() );
    std::copy( mac1.begin(), mac1.end(), stat.mac1.begin() );
    if( !cookie.empty() ) {
      auto mac2_message = make_svv( out.data(), 0, wg_kx1_mac2_message_len );
      auto mac2 = make_svv( out.data(), wg_kx1_mac2_offset, wg_mac_len );
      mac( cookie ).update( mac2_message ).get( mac2 );
    }
    clear_key( kdf_key );
    clear_key( aead_key );
    clear_key( mac_key );
  }

  template< typename In >
  void initiator_hello_phase2( key_state &key, const wg_key_type &self_static_private, const wg_key_type &self_static_public, const wg_key_type &/*remote_static_public*/, uint32_t /*self_spi*/, kx_state &stat, const In &in ) {
    if( in.size() != wg_kx2_len ) throw invalid_packet();
    if( in[ 0 ] != 0x02 ) throw invalid_packet();
    namespace qi = boost::spirit::qi;
    uint32_t remote_spi;
    qi::parse( std::next( in.begin(), wg_kx1_self_spi_offset ), std::next( in.begin(), wg_kx1_self_spi_offset + wg_spi_len ), qi::little_dword, remote_spi );
    auto encrypted_empty = make_svv( in.data(), wg_kx2_encrypted_empty_offset, wg_encrypted_empty_len );
    auto remote_ephemeral_public = make_svv( in.data(), wg_kx2_ephemeral_offset, wg_ephemeral_len );
    wg_key_type kdf_key;
    wg_key_type aead_key;
    wg_key_type q( wg_key_len, 0u );
    wg_key_type t;
    wg_key_type empty;
    wg_key_type calculated_kx2_mac1;
    wg_key_type mac_key;
    auto kx2_mac1_message = make_svv( in.data(), 0, wg_kx2_mac1_message_len );
    auto incoming_kx2_mac1 = make_svv( in.data(), wg_kx2_mac1_offset, wg_mac_len );
    constexpr static char label_mac1[] = "mac1----";
    hash().update( label_mac1, label_mac1 + strlen( label_mac1 ) ).update( self_static_public ).get( mac_key );
    mac( mac_key ).update( kx2_mac1_message ).get( calculated_kx2_mac1 );
    if( !std::equal( calculated_kx2_mac1.begin(), calculated_kx2_mac1.end(), incoming_kx2_mac1.begin(), incoming_kx2_mac1.end() ) )
      throw invalid_packet();
    kdf( stat.chain_key ).update( remote_ephemeral_public ).get( stat.chain_key );
    hash().update( stat.hash_key, remote_ephemeral_public ).get( stat.hash_key );
    dh( kdf_key, stat.self_ephemeral_private, remote_ephemeral_public );
    kdf( stat.chain_key ).update( kdf_key ).get( stat.chain_key );
    dh( kdf_key, self_static_private, remote_ephemeral_public );
    kdf( stat.chain_key ).update( kdf_key ).get( stat.chain_key );
    kdf( stat.chain_key ).update( q ).get( stat.chain_key, t, aead_key );
    hash().update( stat.hash_key, t ).get( stat.hash_key );
    if( !aead_dec( empty, aead_key, 0ull, encrypted_empty, stat.hash_key ) )
      throw invalid_packet();
    hash().update( stat.hash_key, encrypted_empty ).get( stat.hash_key );
    kdf( stat.chain_key ).update( empty ).get( key.send_key, key.receive_key );
    clear_key( kdf_key );
    clear_key( aead_key );
    clear_key( mac_key );
    clear_key( q );
    clear_key( t );
    clear_key( stat.self_ephemeral_private );
    clear_key( stat.self_ephemeral_public );
    clear_key( stat.chain_key );
    clear_key( stat.hash_key );
  }
}

#endif

