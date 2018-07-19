/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#include <cstdio>
#include <iostream>
#include <iterator>
#include <thread>
#include <boost/asio.hpp>
#include <boost/program_options.hpp>
#include <uwg/load_key.hpp>
#include <uwg/dump.hpp>
#include <uwg/initiator.hpp>
#include <uwg/responder.hpp>
#include <uwg/config.hpp>
#include <uwg/session.hpp>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <sys/socket.h> 

struct unable_to_open_tunnel {};
struct unable_to_read_from_tunnel {};
struct unable_to_write_to_tunnel {};
class tunnel {
public:
  tunnel( const std::string &devname ) : fd( 0 ) {
    ifreq ifr;
    if( ( fd = open("/dev/net/tun", O_RDWR) ) < 0 ) {
      std::string device_file_path( "/dev/" );
      device_name = devname.empty() ? std::string( "tun0" ) : devname;
      device_file_path += device_name;
      if( ( fd = open( device_file_path.c_str(), O_RDWR ) ) < 0 )
        throw unable_to_open_tunnel();
    }
    else {
      memset( &ifr, 0, sizeof( ifr ) );
      ifr.ifr_flags = IFF_TUN|IFF_NO_PI;
      if( !devname.empty() )
        strncpy( ifr.ifr_name, devname.c_str(), IFNAMSIZ );
      if( ioctl( fd, TUNSETIFF, (void *) &ifr ) < 0 ) {
        close( fd );
        throw unable_to_open_tunnel();
      }
      device_name = ifr.ifr_name;
    }
  }
  tunnel( const tunnel& ) = delete;
  tunnel( tunnel&& ) = delete;
  tunnel &operator=( const tunnel& ) = delete;
  tunnel &operator=( tunnel&& ) = delete;
  ~tunnel() {
    close( fd );
  }
  template< typename Out >
  void read( Out &out ) {
    out.resize( 1500 );
    int size = ::read( fd, out.data(), out.size() );
    if( size < 0 )
      throw unable_to_read_from_tunnel();
    out.resize( size );
  }
  template< typename In >
  void write( const In &in ) {
    if( !in.empty() ) {
      int size = ::write( fd, in.data(), in.size() );
      if( size < 0 )
        throw unable_to_write_to_tunnel();
    }
  }
private:
  int fd;
  std::string device_name;
};

int main( int argc, char *argv[] ) {
  namespace po = boost::program_options;
  po::options_description opts( "Options" );
  opts.add_options()
    ( "config,c", po::value< std::string >()->default_value( "wireguard.conf" ), "config file path" )
    ( "tunnel,t", po::value< std::string >()->default_value( "tun0" ), "tunnel device name" )
    ( "help,h", "display this message" );
  po::variables_map values;
  po::store( po::parse_command_line( argc, argv, opts ), values );
  if( values.count("help") ) {
    std::cout << opts << std::endl;
    return 0;
  }
  boost::asio::io_service io_service;
  uwg::config_t config( io_service, values[ "config" ].as< std::string >() );
  std::shared_ptr< tunnel > tun( new tunnel( values[ "tunnel" ].as< std::string >() ) );
  tunnel *tun_raw = tun.get();
  uwg::session session( io_service, config,
    [tun,tun_raw]( const boost::asio::ip::udp::endpoint&, std::vector< unsigned char > &&data ) {
      tun_raw->write( data );
    }
  );
  std::thread worker( [&]() { io_service.run(); } );
  boost::container::static_vector< unsigned char, 1500 > buf;
  while( 1 ) {
    tun_raw->read( buf );
    if( !buf.empty() ) {
      session.send( std::move(buf), config.remote_host, config.remote_port, []( uwg::result_t status ) {
        if( status != uwg::result_t::OK ) std::cout << "oops" << std::endl;
      } );
    }
  }
  worker.join();
}

