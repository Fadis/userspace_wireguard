/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_DH_HPP
#define UWG_DH_HPP
#include <type_traits>
#include <sodium/crypto_scalarmult.h>
#include <sodium/randombytes.h>
#include <uwg/defs.hpp>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  template< typename Priv, typename Pub >
  auto dh_generate( Priv &priv, Pub &pub ) -> std::enable_if_t<
    is_continous_memory_container_v< Priv > &&
    is_continous_memory_container_v< Pub >
  > {
    priv.resize( wg_key_len, 0u );
    pub.resize( wg_key_len, 0u );
    randombytes_buf( priv.data(), priv.size() );
    if( crypto_scalarmult_base( pub.data(), priv.data() ) != 0 )
      throw scalar_mult_failed();
  }

  template< typename Out, typename Priv, typename Pub >
  auto dh( Out &out, const Priv &priv, const Pub &pub ) -> std::enable_if_t<
    is_continous_memory_container_v< Out > &&
    is_continous_memory_container_v< Priv > &&
    is_continous_memory_container_v< Pub >
  > {
    out.resize( wg_key_len, 0u );
    if( priv.size() != wg_key_len || pub.size() != wg_key_len )
      throw scalar_mult_failed();
    if( crypto_scalarmult( out.data(), priv.data(), pub.data() ) != 0 )
      throw scalar_mult_failed();
  }
}

#endif

