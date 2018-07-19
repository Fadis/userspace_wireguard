/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_TRANSPORT_HPP
#define UWG_TRANSPORT_HPP
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
  template< typename Out, typename In >
  void encrypt_data( Out &packet, const key_state &key, In &&plain ) {
    const auto packet_size = plain.size()  / 16 * 16 + ( plain.size() % 16 ? 16 : 0 );
    packet.clear();
    packet.resize( packet_size + wg_aead_hash_len + wg_counter_len + wg_spi_len + wg_header_len, 0u );
    packet[ 0 ] = 0x04;
    namespace karma = boost::spirit::karma;
    karma::generate( std::next( packet.begin(), wg_transport_remote_spi_offset ), karma::little_dword, key.remote_kxid );
    karma::generate( std::next( packet.begin(), wg_transport_counter_offset ), karma::little_qword, key.tx_count );
    plain.resize( packet_size, 0u );
    wg_key_type empty;
    auto encrypted = make_svv( packet.data(), wg_transport_packet_offset, packet_size + wg_aead_hash_len );
    aead_enc( encrypted, key.send_key, key.tx_count, plain, empty );
  }
  template< typename Out, typename In >
  bool decrypt_data( Out &plain, key_state &key, const In &packet ) {
    if( packet.size() < wg_transport_packet_offset + wg_aead_hash_len )
      return false;
    if( packet[ 0 ] != 0x04 )
      return false;
    namespace qi = boost::spirit::qi;
    uint64_t counter = 0;
    qi::parse( std::next( packet.begin(), wg_transport_counter_offset ), std::next( packet.begin(), wg_transport_counter_offset + wg_counter_len ), qi::little_qword, counter );
    wg_key_type empty;
    auto encrypted = make_svv( packet.data(), wg_transport_packet_offset, packet.size() - wg_transport_packet_offset );
    if( !aead_dec( plain, key.receive_key, counter, encrypted, empty ) )
      return false;
    if( plain.size() >= 4u ) {
      uint16_t length = 0;
      qi::parse( std::next( plain.begin(), 2 ), std::next( plain.begin(), 4 ), qi::big_word, length );
      if( plain.size() < length )
        return false;
      plain.resize( length );
    }
    return true;
  }
}

#endif

