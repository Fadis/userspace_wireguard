/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_WINDOW_HPP
#define UWG_WINDOW_HPP
#include <cstdint>
#include <iostream>
namespace uwg {
  class window_state {
  public:
    window_state() : highest( 63 ), map( 0 ) {}
    bool get( uint64_t i ) const {
      if( highest < i ) return false;
      else if( highest - i >= 64 ) return true;
      else return ( map >> ( highest - i ) ) & 0x1;
    }
    void set( uint64_t i ) {
      if( highest - i >= 64 ) return;
      else if( highest < i ) {
        if( i - highest >= 64 ) map = 1;
	else {
	  map <<= ( i - highest );
	  map |= 0x01ull;
	}
	highest = i;
      }
      else map |= 0x01ull << ( highest - i );
    }
  private:
    uint64_t highest;
    uint64_t map;
  };
}

#endif

