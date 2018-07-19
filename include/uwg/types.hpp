/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_TYPES_HPP
#define UWG_TYPES_HPP
#include <functional>
#include <memory>
#include <boost/container/static_vector.hpp>
#include <boost/container/flat_map.hpp>
#include <boost/asio.hpp>
#include <boost/asio/system_timer.hpp>
#include <uwg/defs.hpp>
#include <uwg/peer_identifier.hpp>
#include <uwg/window.hpp>

namespace uwg {
  enum class result_t {
    OK,
    FORBIDDEN,
    DISCONNECTED,
    NOT_IMPLEMENTED
  };
  using wg_key_type = boost::container::static_vector< unsigned char, wg_key_len >;
  using wg_tai64n_type = boost::container::static_vector< unsigned char, wg_tai64n_len >;
  using timer_type = boost::asio::system_timer;
  using kxcb_type = std::function< void( result_t ) >;
  struct kx_state {
    kx_state( boost::asio::io_service &ios ) : timer( new timer_type( ios ) ), cb( []( result_t ){} ) {}
    wg_key_type self_ephemeral_private;
    wg_key_type self_ephemeral_public;
    wg_key_type chain_key;
    wg_key_type hash_key;
    wg_key_type cookie;
    wg_key_type mac1;
    std::shared_ptr< timer_type > timer;
    kxcb_type cb;
  };
  using kx_states = boost::container::flat_map< peer_identifier, kx_state >;
  struct responder_state {
    responder_state() : cookie_since( 0 ) {}
    wg_key_type cookie;
    time_t cookie_since;
  };
  using responder_states = boost::container::flat_map< peer_identifier, responder_state >;
  struct key_state {
    key_state() : since( 0 ), tx_count( 0 ) {}
    key_state( boost::asio::io_service &ios ) : timer( new timer_type( ios ) ), since( 0 ), tx_count( 0 ) {}
    wg_key_type send_key;
    wg_key_type receive_key;
    std::shared_ptr< timer_type > timer;
    time_t since;
    size_t tx_count;
    uint32_t remote_kxid;
    window_state window;
  };
  using key_ring_t = boost::container::flat_map< peer_identifier, std::shared_ptr< key_state > >;
  struct peer_state {
    peer_state() : timestamp( wg_tai64n_len, 0 ) {}
    peer_state( const wg_tai64n_type &ts ) : timestamp( ts.begin(), ts.end() ) {}
    wg_tai64n_type timestamp;
  };
  struct key_comp {
    bool operator()( const wg_key_type &l, const  wg_key_type &r ) const {
      const auto min_size = std::min( l.size(), r.size() );
      const auto data_diff = memcmp( l.data(), r.data(), min_size );
      if( data_diff == 0 ) return l.size() < r.size();
      else return data_diff < 0;
    }
  };
  using peer_states = boost::container::flat_map< wg_key_type, peer_state, key_comp >;
}

#endif
