/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_CONFIG_HPP
#define UWG_CONFIG_HPP

#include <string>
#include <boost/property_tree/ini_parser.hpp>
#include <boost/spirit/include/qi_parse.hpp>
#include <boost/spirit/include/qi_uint.hpp>
#include <boost/asio.hpp>
#include <sodium/crypto_scalarmult.h>
#include <uwg/load_key.hpp>
#include <uwg/types.hpp>
#include <uwg/defs.hpp>

namespace uwg {
  struct invalid_config {};
  struct invalid_key {};
  struct invalid_endpoint {};
  struct invalid_listen_port {};
  struct config_t {
    config_t( boost::asio::io_service &io_service, const std::string &filename ) : self_static_public( wg_key_len, 0 ), self_port( 0 ) {
      boost::property_tree::ptree root;
      boost::property_tree::read_ini( filename, root );
      const auto self_static_private_serialized = root.get_optional< std::string >( "Interface.PrivateKey" );
      if( !self_static_private_serialized )
        throw invalid_key();
      const auto listen_port = root.get_optional< uint16_t >( "Interface.ListenPort" );
      if( !listen_port )
        throw invalid_listen_port();
      const auto remote_static_public_serialized = root.get_optional< std::string >( "Peer.PublicKey" );
      if( !remote_static_public_serialized )
        throw invalid_key();
      const auto remote_address = root.get_optional< std::string >( "Peer.Endpoint" );
      if( !remote_address )
        throw invalid_endpoint();
      parse_key( self_static_private_serialized->begin(), self_static_private_serialized->end(), std::back_inserter( self_static_private ) );
      parse_key( remote_static_public_serialized->begin(), remote_static_public_serialized->end(), std::back_inserter( remote_static_public ) );
      if( self_static_private.size() != wg_key_len )
        throw invalid_key();
      if( remote_static_public.size() != wg_key_len )
        throw invalid_key();
      if( crypto_scalarmult_base( self_static_public.data(), self_static_private.data() ) != 0 )
        throw scalar_mult_failed();
      const auto remote_address_sep = remote_address->find( ':' );
      if( remote_address_sep == std::string::npos )
        throw invalid_endpoint();
      remote_host = remote_address->substr( 0, remote_address_sep );
      remote_port = remote_address->substr( remote_address_sep + 1 );
      boost::asio::ip::udp::resolver resolver( io_service );
      boost::asio::ip::udp::resolver::query query( remote_host, remote_port );
      remote_endpoint = *resolver.resolve( query );
      self_port = *listen_port;
    }
    wg_key_type self_static_private;
    wg_key_type self_static_public;
    wg_key_type remote_static_public;
    std::string remote_host;
    boost::asio::ip::udp::endpoint remote_endpoint;
    uint16_t self_port;
    std::string remote_port;
  };
}

#endif

