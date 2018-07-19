/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_STATIC_VECTOR_HPP
#define UWG_STATIC_VECTOR_HPP
#include <iostream>
#include <array>
#include <cstdlib>
#include <iterator>
#include <algorithm>

namespace uwg {
  template< typename T >
  class static_vector_view {
  public:
    using iterator = T*;
    using const_iterator = const T*;
    using size_type = size_t;
    using difference_type = int;
    using value_type = T;
    using reference = T&;
    using const_reference = const T&;
    using pointer = T*;
    using const_pointer = const T*;
    static_vector_view( T *begin_addr_, T *end_addr_ ) : begin_addr( begin_addr_ ), end_addr( end_addr_ ), current_size( end_addr_ - begin_addr_ ) {}
    iterator begin() { return begin_addr; }
    iterator end() { return end_addr; }
    const_iterator begin() const { return begin_addr; }
    const_iterator end() const { return std::next( begin_addr, current_size ); }
    const_iterator cbegin() const { return begin_addr; }
    const_iterator cend() const { return end_addr; }
    size_type size() const { return current_size; }
    size_type empty() const { return current_size = 0u; }
    size_type capacity() const { return end_addr - begin_addr; }
    pointer data() { return begin_addr; }
    const_pointer data() const { return begin_addr; }
    void resize( size_type new_size ) {
      if( new_size > capacity() ) throw std::bad_alloc();
      current_size = new_size;
    }
    void resize( size_type new_size, const_reference v ) {
      if( new_size > capacity() ) throw std::bad_alloc();
      const auto old_size = current_size;
      std::fill( std::next( begin_addr, old_size ), std::next( begin_addr, new_size ), v );
      current_size = new_size;
    }
    void clear() { current_size = 0; }
    reference at( size_type i ) { return begin_addr[ i ]; }
    const_reference at( size_type i ) const { return begin_addr[ i ]; }
  private:
    T *begin_addr;
    T *end_addr;
    size_t current_size;
  };
  template< typename T >
  static_vector_view< T > make_svv( T *head, size_t offset, size_t size ) {
    return static_vector_view< T >( std::next( head, offset ), std::next( head, offset + size ) );
  }
}

#endif

