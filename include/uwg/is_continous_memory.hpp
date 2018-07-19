/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_IS_CONTINOUS_MEMORY_RANGE_HPP
#define UWG_IS_CONTINOUS_MEMORY_RANGE_HPP
#include <type_traits>
#include <utility>

namespace uwg {
  template< typename T, typename Enable = void >
  struct is_continous_memory_container : std::false_type {};
  template< typename T >
  struct is_continous_memory_container<
    T,
    typename std::enable_if<
      std::is_pointer< decltype(
        std::declval< T >().begin(),
        std::declval< T >().end(),
        std::declval< T >().clear(),
        std::declval< T >().resize( 1u ),
        std::declval< T >().data()
      ) >::value &&
      std::is_integral< decltype( std::declval< T >().size() ) >::value
    >::type
  > : std::true_type {};
  template< typename T >
  using is_continous_memory_container_t = typename is_continous_memory_container< T >::type;
  template< typename T >
  constexpr bool is_continous_memory_container_v = is_continous_memory_container< T >::value;
}

#endif

