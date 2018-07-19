/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_LOAD_KEY_HPP
#define UWG_LOAD_KEY_HPP

#include <string>
#include <fstream>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <uwg/defs.hpp>

namespace uwg {
  template< typename InIter, typename OutIter >
  void parse_key( const InIter &encoded_begin, const InIter &encoded_end, OutIter out ) {
    namespace bait = boost::archive::iterators;
    using base_iter = InIter;
    using b64_iter = bait::transform_width< bait::binary_from_base64< base_iter >, 8, 6, unsigned char>;
    auto decoded_begin = b64_iter( encoded_begin );
    auto decoded_end = b64_iter( encoded_end );
    size_t count = 0u;
    for( auto iter = decoded_begin; iter != decoded_end && count != wg_key_len; ++iter, ++count, ++out )
      *out = *iter;
  }
  
  template< typename OutIter >
  void load_key( const std::string &filename, OutIter out ) {
    namespace bait = boost::archive::iterators;
    using base_iter = std::istreambuf_iterator< char >;
    std::fstream key_file( filename, std::ios::in | std::ios::binary );
    parse_key( base_iter( key_file ), base_iter(), out );
  }
}

#endif

