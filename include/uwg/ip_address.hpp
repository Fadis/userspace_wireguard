/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_IP_ADDRESS_HPP
#define UWG_IP_ADDRESS_HPP

#include <cstdint>

namespace uwg {
  struct ip_address {
  public:
    ip_address() : version( 4 ), high( 0 ), low( 0 ) {}
    uint8_t version;
    uint64_t high;
    uint64_t low;
  };
  bool operator==( const ip_address &l, const ip_address &r ) {
    return l.version == r.version && l.high == r.high && l.low == r.low;
  }
  bool operator!=( const ip_address &l, const ip_address &r ) {
    return l.version != r.version || l.high != r.high || l.low == r.low;
  }
  bool operator<( const ip_address &l, const ip_address &r ) {
    if( l.version == r.version ) {
      if( l.high == r.high ) return l.low < r.low;
      else return l.high < r.high;
    }
    else return l.version < r.version;
  }
  bool operator>( const ip_address &l, const ip_address &r ) {
    if( l.version == r.version ) {
      if( l.high == r.high ) return l.low > r.low;
      else return l.high > r.high;
    }
    else return l.version > r.version;
  }
  bool operator<=( const ip_address &l, const ip_address &r ) {
    if( l.version == r.version ) {
      if( l.high == r.high ) return l.low <= r.low;
      else return l.high < r.high;
    }
    else return l.version < r.version;
  }
  bool operator>=( const ip_address &l, const ip_address &r ) {
    if( l.version == r.version ) {
      if( l.high == r.high ) return l.low >= r.low;
      else return l.high > r.high;
    }
    else return l.version > r.version;
  }
}

#endif

