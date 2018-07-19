/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_XAEAD_HPP
#define UWG_XAEAD_HPP
#include <type_traits>
#include <sodium/randombytes.h>
#include <sodium/crypto_aead_xchacha20poly1305.h>
#include <uwg/defs.hpp>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  template< typename Out >
  void xaead_generate_nonce( Out &out ) {
    out.resize( 24 );
    randombytes_buf( out.data(), out.size() );
  }
  template< typename Out, typename Key, typename Nonce, typename Plain, typename Auth >
  void xaead_enc( Out &out, const Key &key, const Nonce &nonce, const Plain &plain, const Auth &auth ) {
    unsigned long long out_size;
    out.resize( plain.size() + crypto_aead_xchacha20poly1305_IETF_ABYTES );
    crypto_aead_xchacha20poly1305_ietf_encrypt( out.data(), &out_size, plain.data(), plain.size(), auth.data(), auth.size(), nullptr, nonce.data(), key.data() );
    out.resize( out_size );
  }

  template< typename Out, typename Key, typename Nonce, typename Encrypted, typename Auth >
  bool xaead_dec( Out &out, const Key &key, const Nonce &nonce, const Encrypted &encrypted, const Auth &auth ) {
    unsigned long long out_size;
    out.resize( encrypted.size() - crypto_aead_xchacha20poly1305_IETF_ABYTES );
    if( crypto_aead_xchacha20poly1305_ietf_decrypt( out.data(), &out_size, nullptr, encrypted.data(), encrypted.size(), auth.data(), auth.size(), nonce.data(), key.data() ) < 0 )
      return false;
    out.resize( out_size );
    return true;
  }
}

#endif

