#ifndef UWG_SESSION_HPP
#define UWG_SESSION_HPP
#include <iostream>
#include <iterator>
#include <boost/asio.hpp>
#include <uwg/load_key.hpp>
#include <uwg/dump.hpp>
#include <uwg/initiator.hpp>
#include <uwg/responder.hpp>
#include <uwg/transport.hpp>
#include <uwg/cookie.hpp>
#include <uwg/config.hpp>

#define likely(x)   __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)

namespace uwg {
  class session {
  public:
    using receiver_cb_t = std::function< void( const boost::asio::ip::udp::endpoint&, std::vector< unsigned char >&& ) >;
    session( boost::asio::io_service &ios, const config_t &config_, const receiver_cb_t &receiver_ ) : io_service( ios ), socket( ios, boost::asio::ip::udp::endpoint( boost::asio::ip::udp::v4(), config_.self_port ) ), next_kxid( 0u ), config( config_ ), end_flag( false ), receiver( receiver_ ) {
      receive();
    }
    template< typename In >
    void send( In &&in, const std::string &host, const std::string &port, const kxcb_type &cb ) {
      std::shared_ptr< key_state > key;
      using boost::asio::ip::udp;
      udp::resolver resolver( io_service );
      udp::resolver::query query( config.remote_host, config.remote_port );
      const auto remote_endpoint = *resolver.resolve( query );
      bool waiting_for_kx = false;
      if( host != config.remote_host || port != config.remote_port ) {
        cb( result_t::DISCONNECTED );
	return;
      }
      {
        std::lock_guard< std::mutex > lock( guard );
	{
          const auto key_begin = key_ring.lower_bound( peer_identifier( remote_endpoint, 0 ) );
          if( key_begin != key_ring.end() && key_begin->first.endpoint == remote_endpoint ) {
            const auto key_end = std::find_if( key_begin, key_ring.end(), [remote_endpoint]( const auto &v ) { return v.first.endpoint != remote_endpoint; } );
	    const auto latest_key = std::prev( key_end );
            key = latest_key->second;
            ++latest_key->second->tx_count;
          }
	}
	{
          const auto search_result = active_kx.lower_bound( peer_identifier( remote_endpoint, 0 ) );
	  if( search_result != active_kx.end() && search_result->first.endpoint == remote_endpoint )
	    waiting_for_kx = true;
	}
      }
      const time_t now = time( nullptr );
      if( likely( key && ( now - key->since ) < 120 && key->tx_count < std::numeric_limits< uint64_t >::max() - 0x10000ull ) ) {
        boost::container::static_vector< unsigned char, 2048u > packet;
        uwg::encrypt_data( packet, *key, std::move(in) );
        socket.async_send_to( boost::asio::buffer( packet.data(), packet.size() ),
	  remote_endpoint,
          [cb]( const boost::system::error_code& error, size_t ) {
            if( unlikely( error ) ) cb( result_t::DISCONNECTED );
            else cb( result_t::OK );
          }
        );
      }
      else if( key && ( now - key->since ) < 180 && key->tx_count < std::numeric_limits< uint64_t >::max() - 0x10ull ) {
        boost::container::static_vector< unsigned char, 2048u > packet;
        uwg::encrypt_data( packet, *key, std::move(in) );
        socket.async_send_to( boost::asio::buffer( packet.data(), packet.size() ),
	  remote_endpoint,
          [cb]( const boost::system::error_code& error, size_t ) {
            if( unlikely( error ) ) cb( result_t::DISCONNECTED );
            else cb( result_t::OK );
          }
        );
	if( !waiting_for_kx )
          initiator_hello( []( result_t ) {} );
      }
      else {
        initiator_hello( [this,in=std::move(in),host,port,cb]( result_t status ) mutable {
          if( unlikely( status != result_t::OK ) ) {
	    cb( status );
	  }
          else {
	    send( std::move( in ), host, port, cb );
	  }
        } );
      }
    }
  private:
    void receive() {
      std::shared_ptr< boost::container::static_vector< uint8_t, 2048u > > data( new boost::container::static_vector< uint8_t, 2048u >( 2048u ) );
      using boost::asio::ip::udp;
      std::shared_ptr< udp::endpoint > from( new udp::endpoint() );
      socket.async_receive_from(
        boost::asio::buffer( data->data(), data->size() ),
        *from,
        [this,data,from](
          const boost::system::error_code& error,
          size_t size
        ) {
          if( likely( !error ) ) {
	    boost::container::static_vector< uint8_t, 2048u > *data_raw = data.get();
	    udp::endpoint *from_raw = from.get();
            data_raw->resize( size );
            if( unlikely( (*data_raw)[ 0 ] == 0x1 ) ) {
	      if( unlikely( data_raw->size() != wg_kx1_len ) ) return;
	      uint32_t remote_kxid;
	      namespace qi = boost::spirit::qi;
              qi::parse( std::next( data_raw->begin(), wg_kx1_self_spi_offset ), std::next( data_raw->begin(), wg_kx1_self_spi_offset + wg_spi_len ), qi::little_dword, remote_kxid );
              boost::container::static_vector< unsigned char, wg_kx2_len > hello;
              std::shared_ptr< key_state > key( new key_state( io_service ) );
	      uint32_t kxid = 0;
              try {
                std::lock_guard< std::mutex > lock( guard );
                if( unlikely( end_flag ) ) return;
                kxid = ++next_kxid;
                if( unlikely( config.remote_endpoint != *from_raw ) ) return;
                const time_t now = time( nullptr );
                if( cookie_timestamp && now - cookie_timestamp > 120 ) {
                  cookie_timestamp = 0;
                  cookie.clear();
                }
                uwg::responder_hello( *key, hello, peers, config.self_static_private, config.self_static_public, config.remote_static_public, kxid, cookie, *data_raw );
              } catch( const invalid_packet& ) { return; }
              key->timer->expires_from_now( std::chrono::seconds( 10 ) );
              key->timer->async_wait(
                [this,pi=peer_identifier( *from_raw, kxid )]( const boost::system::error_code &error ) {
		  if( !error ) {
		    bool need_keepalive = false;
                    boost::container::static_vector< unsigned char, 2048u > packet;
		    {
                      std::lock_guard< std::mutex > lock( guard );
                      const auto search_result = key_ring.find( pi );
                      if( search_result != key_ring.end() ) {
		        need_keepalive = search_result->second->tx_count == 0;
			if( need_keepalive ) {
                          auto key = search_result->second;
		          std::vector< unsigned char > empty;
                          uwg::encrypt_data( packet, *key, std::move( empty ) );
			}
	              }
		    }
		    if( need_keepalive ) {
                      socket.async_send_to( boost::asio::buffer( packet.data(), packet.size() ),
                        remote_endpoint,
                        []( const boost::system::error_code&, size_t ) {}
                      );
		    }
                  }
		}
	      );
              key->since = time( nullptr );
              key->remote_kxid = remote_kxid;
              socket.async_send_to( boost::asio::buffer( hello.data(), hello.size() ),
                *from_raw,
                [this,from_raw,kxid,key]( const boost::system::error_code& error, size_t ) {
                  if( unlikely( !error ) ) {
                    std::lock_guard< std::mutex > lock( guard );
                    const auto key_begin = key_ring.lower_bound( peer_identifier( *from_raw, 0 ) );
                    if( key_begin != key_ring.end() && key_begin->first.endpoint == *from_raw ) {
                      const auto key_end = std::find_if( key_begin, key_ring.end(), [from_raw]( const auto &v ) { return v.first.endpoint != *from_raw; } );
                      if( std::distance( key_begin, key_end ) >= 2 )
                        key_ring.erase( key_begin, std::prev( key_end ) );
                    }
                    key_ring.insert( std::make_pair( peer_identifier( *from_raw, kxid ), key ) );
                  }
                }
              );
            }
            else if( unlikely( (*data_raw)[ 0 ] == 0x2 ) ) {
	      if( unlikely( data_raw->size() != wg_kx2_len ) ) return;
              uint32_t original_kxid;
              uint32_t remote_kxid;
	      namespace qi = boost::spirit::qi;
              qi::parse( std::next( data_raw->begin(), wg_kx2_remote_spi_offset ), std::next( data_raw->begin(), wg_kx2_remote_spi_offset + wg_spi_len ), qi::little_dword, original_kxid );
              qi::parse( std::next( data_raw->begin(), wg_kx2_self_spi_offset ), std::next( data_raw->begin(), wg_kx2_self_spi_offset + wg_spi_len ), qi::little_dword, remote_kxid );
	      const peer_identifier peer ( *from_raw, original_kxid );
              std::shared_ptr< key_state > key( new key_state( io_service ) );
              key->since = time( nullptr );
              key->remote_kxid = remote_kxid;
              kxcb_type cb = []( result_t ) {};
	      try {
                {
                  std::lock_guard< std::mutex > lock( guard );
                  if( unlikely( end_flag ) ) return;
                  const auto search_result = active_kx.find( peer );
                  if( unlikely( search_result != active_kx.end() ) ) {
                    uwg::initiator_hello_phase2( *key, config.self_static_private, config.self_static_public, config.remote_static_public, original_kxid, search_result->second, *data_raw );
                    const auto key_begin = key_ring.lower_bound( peer_identifier( *from_raw, 0 ) );
                    if( key_begin != key_ring.end() && key_begin->first.endpoint == *from_raw ) {
                      const auto key_end = std::find_if( key_begin, key_ring.end(), [from_raw]( const auto &v ) { return v.first.endpoint != *from_raw; } );
                      if( std::distance( key_begin, key_end ) >= 2 )
                        key_ring.erase( key_begin, std::prev( key_end ) );
                    }
                    key_ring.insert( std::make_pair( peer, key ) );
                    cb = search_result->second.cb;
	            active_kx.erase( search_result );
                  }
                }
                cb( result_t::OK );
	      } catch( const invalid_packet& ) {}
            }
            else if( unlikely( (*data_raw)[ 0 ] == 0x3 ) ) {
	      if( unlikely( data_raw->size() != wg_kx2_len ) ) return;
              uint32_t original_kxid;
	      namespace qi = boost::spirit::qi;
              qi::parse( std::next( data_raw->begin(), wg_cookie_remote_spi_offset ), std::next( data_raw->begin(), wg_cookie_remote_spi_offset + wg_spi_len ), qi::little_dword, original_kxid );
	      const peer_identifier peer ( *from_raw, original_kxid );
              kxcb_type cb = []( result_t ) {};
              try {
	        {
                  std::lock_guard< std::mutex > lock( guard );
                  if( unlikely( end_flag ) ) return;
                  const auto search_result = active_kx.find( peer );
                  if( unlikely( search_result != active_kx.end() ) ) {
                    uwg::parse_cookie( cookie, config.self_static_public, search_result->second.mac1, *data_raw );
		    cookie_timestamp = time( nullptr );
                    cb = search_result->second.cb;
                  }
                }
                initiator_hello( cb );
	      } catch( const invalid_packet& ) {}
            }
            else if( likely( (*data_raw)[ 0 ] == 0x4 ) ) {
              std::shared_ptr< key_state > key;
              uint32_t kxid;
	      namespace qi = boost::spirit::qi;
              qi::parse( std::next( data_raw->begin(), wg_transport_remote_spi_offset ), std::next( data_raw->begin(), wg_transport_remote_spi_offset + wg_spi_len ), qi::little_dword, kxid );
	      uint64_t counter;
              qi::parse( std::next( data_raw->begin(), wg_transport_counter_offset ), std::next( data_raw->begin(), wg_transport_counter_offset + wg_counter_len ), qi::little_qword, counter );
	      const peer_identifier peer( *from_raw, kxid );
	      bool duplicated = false;
              {
                std::lock_guard< std::mutex > lock( guard );
                if( unlikely( end_flag ) ) return;
                const auto search_result = key_ring.find( peer );
                if( search_result != key_ring.end() ) {
                  key = search_result->second;
                  duplicated = key->window.get( counter );
		}
              }
	      if( !duplicated ) {
                const time_t now = time( nullptr );
                if( likely( key && ( now - key->since ) < 180 ) ) {
                  std::vector< unsigned char > decrypted;
                  if( uwg::decrypt_data( decrypted, *key, *data_raw ) ) {
                    {
                      std::lock_guard< std::mutex > lock( guard );
                      key->window.set( counter );
	            }
                    receiver( *from_raw, std::move( decrypted ) );
                  }
                }
	      }
            }
            receive();
          }
        }
      );
    }
    void initiator_hello( const kxcb_type &cb ) {
      boost::container::static_vector< unsigned char, wg_kx1_len > hello;
      size_t kxid = 0u;
      peer_identifier pi( config.remote_endpoint, 0 );
      {
        std::lock_guard< std::mutex > lock( guard );
        kxid = ++next_kxid;
	pi.kxid = kxid;
        const auto result = active_kx.emplace( pi, kx_state( io_service ) );
        const auto iter = result.first;
        iter->second.cb = cb;
	const time_t now = time( nullptr );
	if( cookie_timestamp && now - cookie_timestamp > 120 ) {
	  cookie_timestamp = 0;
	  cookie.clear();
	}
        initiator_hello_phase1( iter->second, hello, config.self_static_private, config.self_static_public, config.remote_static_public, kxid, cookie );
        iter->second.timer->expires_from_now( std::chrono::seconds( 120 ) );
        iter->second.timer->async_wait(
          [this,pi]( const boost::system::error_code& ) {
            kxcb_type cb = []( result_t ) {};
            std::lock_guard< std::mutex > lock( guard );
            const auto search_result = active_kx.find( pi );
            if( search_result != active_kx.end() ) {
              cb = search_result->second.cb;
              active_kx.erase( search_result );
            }
            cb( result_t::DISCONNECTED );
          }
        );
      }
      socket.async_send_to( boost::asio::buffer( hello.data(), hello.size() ),
        config.remote_endpoint,
        [this,pi]( const boost::system::error_code& error, size_t ) {
          if( unlikely( error ) ) {
            kxcb_type cb = []( result_t ) {};
            {
              std::lock_guard< std::mutex > lock( guard );
              const auto search_result = active_kx.find( pi );
              if( search_result != active_kx.end() ) {
                cb = search_result->second.cb;
                active_kx.erase( search_result );
              }
            }
            cb( result_t::DISCONNECTED );
          }
        }
      );
    }
    std::mutex guard;
    boost::asio::io_service &io_service;
    boost::asio::ip::udp::socket socket;
    boost::asio::ip::udp::endpoint remote_endpoint;
    uwg::wg_key_type cookie;
    time_t cookie_timestamp;
    kx_states active_kx;
    key_ring_t key_ring;
    size_t next_kxid;
    config_t config;
    bool end_flag;
    receiver_cb_t receiver;
    peer_states peers;
  };
}

#endif

