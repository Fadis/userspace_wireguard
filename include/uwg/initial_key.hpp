/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_INITIAL_KEY_HPP
#define UWG_INITIAL_KEY_HPP
#include <type_traits>
#include <uwg/defs.hpp>
#include <uwg/hash.hpp>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  template< typename Out >
  auto get_initial_chain_key( Out &out ) -> std::enable_if_t< is_continous_memory_container_v< Out > > {
    constexpr char construction[] = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
    hash().update( construction, construction + strlen( construction ) ).get( out );
  }

  template< typename Out, typename Chain >
  auto get_initial_hash_key( Out &out, const Chain &chain_key ) -> std::enable_if_t< is_continous_memory_container_v< Out > && is_continous_memory_container_v< Chain > > {
    constexpr char identifier[] = "WireGuard v1 zx2c4 Jason@zx2c4.com";
    hash().update( chain_key ).update( identifier, identifier + strlen( identifier ) ).get( out );
  }
}

#endif

