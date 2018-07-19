/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_CLEAR_KEY_HPP
#define UWG_CLEAR_KEY_HPP

#include <algorithm>

namespace uwg {
  template< typename Out >
  void clear_key( Out &out ) {
    out.resize( wg_key_len );
    std::fill( out.begin(), out.end(), 0u );
    out.resize( 0u );
  }
}

#endif

