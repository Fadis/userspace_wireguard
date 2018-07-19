/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_AEAD_HPP
#define UWG_AEAD_HPP
#include <type_traits>
#include <sodium/crypto_aead_chacha20poly1305.h>
#include <uwg/defs.hpp>
#include <uwg/is_continous_memory.hpp>

namespace uwg {
  template< typename Out, typename Key, typename Plain, typename Auth >
  void aead_enc( Out &out, const Key &key, uint64_t counter, const Plain &plain, const Auth &auth ) {
    unsigned long long out_size;
    std::array< unsigned char, 12 > counter_{{ 0 }};
    namespace karma = boost::spirit::karma;
    karma::generate( std::next( counter_.begin(), 4 ), karma::little_qword, counter );
    out.resize( plain.size() + crypto_aead_chacha20poly1305_IETF_ABYTES );
    crypto_aead_chacha20poly1305_ietf_encrypt( out.data(), &out_size, plain.data(), plain.size(), auth.data(), auth.size(), nullptr, counter_.data(), key.data() );
    out.resize( out_size );
  }

  template< typename Out, typename Key, typename Encrypted, typename Auth >
  bool aead_dec( Out &out, const Key &key, uint64_t counter, const Encrypted &encrypted, const Auth &auth ) {
    unsigned long long out_size;
    std::array< unsigned char, 12 > counter_{{ 0 }};
    namespace karma = boost::spirit::karma;
    karma::generate( std::next( counter_.begin(), 4 ), karma::little_qword, counter );
    out.resize( encrypted.size() - crypto_aead_chacha20poly1305_IETF_ABYTES );
    if( crypto_aead_chacha20poly1305_ietf_decrypt( out.data(), &out_size, nullptr, encrypted.data(), encrypted.size(), auth.data(), auth.size(), counter_.data(), key.data() ) < 0 )
      return false;
    out.resize( out_size );
    return true;
  }
}

#endif

