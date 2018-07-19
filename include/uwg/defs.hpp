/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_DEFS_HPP
#define UWG_DEFS_HPP

namespace uwg {
  struct invalid_packet {};
  struct unable_to_get_current_date {};
  struct scalar_mult_failed {};
  constexpr size_t wg_header_len = 4u;
  constexpr size_t wg_spi_len = 4u;
  constexpr size_t wg_key_len = 32u;
  constexpr size_t wg_ephemeral_len = wg_key_len;
  constexpr size_t wg_aead_hash_len = 16u;
  constexpr size_t wg_tai64n_len = 12u;
  constexpr size_t wg_encrypted_tai64n_len = wg_tai64n_len + wg_aead_hash_len;
  constexpr size_t wg_static_len = wg_key_len;
  constexpr size_t wg_encrypted_static_len = wg_static_len + wg_aead_hash_len;
  constexpr size_t wg_encrypted_empty_len = wg_aead_hash_len;
  constexpr size_t wg_mac_len = 16u;
  constexpr size_t wg_counter_len = 8u;
  constexpr size_t wg_nonce_len = 24u;
  constexpr size_t wg_encrypted_cookie_len = wg_mac_len + wg_aead_hash_len;
  constexpr size_t wg_kx1_len = wg_header_len + wg_spi_len + wg_ephemeral_len + wg_encrypted_static_len + wg_encrypted_tai64n_len + wg_mac_len + wg_mac_len;
  constexpr size_t wg_kx1_mac1_message_len = wg_header_len + wg_spi_len + wg_ephemeral_len + wg_encrypted_static_len + wg_encrypted_tai64n_len;
  constexpr size_t wg_kx1_mac2_message_len = wg_header_len + wg_spi_len + wg_ephemeral_len + wg_encrypted_static_len + wg_encrypted_tai64n_len + wg_mac_len;
  constexpr size_t wg_kx2_len = wg_header_len + wg_spi_len + wg_spi_len + wg_ephemeral_len + wg_encrypted_empty_len + wg_mac_len + wg_mac_len;
  constexpr size_t wg_kx2_mac1_message_len = wg_header_len + wg_spi_len + wg_spi_len + wg_ephemeral_len + wg_encrypted_empty_len;
  constexpr size_t wg_kx2_mac2_message_len = wg_header_len + wg_spi_len + wg_spi_len + wg_ephemeral_len + wg_encrypted_empty_len + wg_mac_len;
  constexpr size_t wg_cookie_len = wg_header_len + wg_spi_len + wg_nonce_len + wg_encrypted_cookie_len;
  constexpr size_t wg_kx1_self_spi_offset = wg_header_len;
  constexpr size_t wg_kx1_ephemeral_offset = wg_kx1_self_spi_offset + wg_spi_len;
  constexpr size_t wg_kx1_encrypted_static_offset = wg_kx1_ephemeral_offset + wg_ephemeral_len;
  constexpr size_t wg_kx1_encrypted_tai64n_offset = wg_kx1_encrypted_static_offset + wg_encrypted_static_len;
  constexpr size_t wg_kx1_mac1_offset = wg_kx1_encrypted_tai64n_offset + wg_encrypted_tai64n_len;
  constexpr size_t wg_kx1_mac2_offset = wg_kx1_mac1_offset + wg_mac_len;
  constexpr size_t wg_kx2_self_spi_offset = wg_header_len;
  constexpr size_t wg_kx2_remote_spi_offset = wg_kx2_self_spi_offset + wg_spi_len;
  constexpr size_t wg_kx2_ephemeral_offset = wg_kx2_remote_spi_offset + wg_spi_len;
  constexpr size_t wg_kx2_encrypted_empty_offset = wg_kx2_ephemeral_offset + wg_ephemeral_len;
  constexpr size_t wg_kx2_mac1_offset = wg_kx2_encrypted_empty_offset + wg_encrypted_empty_len;
  constexpr size_t wg_kx2_mac2_offset = wg_kx2_mac1_offset + wg_mac_len;
  constexpr size_t wg_transport_remote_spi_offset = wg_header_len;
  constexpr size_t wg_transport_counter_offset = wg_transport_remote_spi_offset + wg_spi_len;
  constexpr size_t wg_transport_packet_offset = wg_transport_counter_offset + wg_counter_len;
  constexpr size_t wg_cookie_remote_spi_offset = wg_header_len;
  constexpr size_t wg_cookie_nonce_offset = wg_cookie_remote_spi_offset + wg_spi_len;
  constexpr size_t wg_cookie_cookie_offset = wg_cookie_nonce_offset + wg_nonce_len;
}

#endif

