/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_TIMESTAMP_HPP
#define UWG_TIMESTAMP_HPP

#include <cstdint>
#include <ctime>
#include <boost/spirit/include/karma.hpp>

namespace uwg {
  template< typename OutIter >
  void timestamp( OutIter iter ) {
    timespec ts;
    if( clock_gettime( CLOCK_TAI, &ts ) != 0 )
      throw unable_to_get_current_date();
    const uint64_t tai64 = 0x4000000000000000ll + int64_t( ts.tv_sec );
    namespace karma = boost::spirit::karma;
    karma::generate( iter, karma::big_qword << karma::big_dword, boost::fusion::make_vector( tai64, ts.tv_nsec ) );
  }
}

#endif

