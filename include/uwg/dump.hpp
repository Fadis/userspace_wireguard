/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_DUMP_HPP
#define UWG_DUMP_HPP

#include <iostream>
#include <boost/spirit/include/karma.hpp>

namespace uwg {
template< typename In >
  void dump( const In &in ) {
    namespace karma = boost::spirit::karma;
    std::cout << karma::format( *( karma::right_align( 2, '0' )[ karma::hex ] << ' ' ), in ) << std::endl;
  }
}

#endif

