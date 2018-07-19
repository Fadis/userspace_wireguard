/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_PEER_IDENTIFIER_HPP
#define UWG_PEER_IDENTIFIER_HPP

#include <cstdint>
#include <string>
#include <boost/asio.hpp>

namespace uwg {
  using kxid_t = uint32_t;
  struct peer_identifier {
    peer_identifier() : kxid( 0 ) {}
    peer_identifier( const boost::asio::ip::udp::endpoint &e, kxid_t i ) : endpoint( e ), kxid( i ) {}
    boost::asio::ip::udp::endpoint endpoint;
    kxid_t kxid;
  };

  bool operator==( const peer_identifier &l, const peer_identifier &r ) {
    return l.endpoint == r.endpoint && l.kxid == r.kxid;
  }
  bool operator!=( const peer_identifier &l, const peer_identifier &r ) {
    return l.endpoint != r.endpoint || l.kxid == r.kxid;
  }
  bool operator<( const peer_identifier &l, const peer_identifier &r ) {
    if( l.endpoint == r.endpoint ) return l.kxid < r.kxid;
    else return l.endpoint < r.endpoint;
  }
  bool operator>( const peer_identifier &l, const peer_identifier &r ) {
    if( l.endpoint == r.endpoint ) return l.kxid > r.kxid;
    else return l.endpoint > r.endpoint;
  }
  bool operator<=( const peer_identifier &l, const peer_identifier &r ) {
    if( l.endpoint == r.endpoint ) return l.kxid <= r.kxid;
    else return l.endpoint < r.endpoint;
  }
  bool operator>=( const peer_identifier &l, const peer_identifier &r ) {
    if( l.endpoint == r.endpoint ) return l.kxid >= r.kxid;
    else return l.endpoint < r.endpoint;
  }
}

#endif

