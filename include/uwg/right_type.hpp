/*
 *  Copyright (C) 2018 Naomasa Matsubayashi
 *  Licensed under MIT license, see file LICENSE in this source tree.
 */
#ifndef UWG_RIGHT_TYPE_HPP
#define UWG_RIGHT_TYPE_HPP

namespace uwg {
  template< typename ...Args >
  struct right_type;
  template< typename Head, typename Next, typename ...Tail >
  struct right_type< Head, Next, Tail... > {
    using type = typename right_type< Next, Tail... >::type;
  };
  template< typename Head >
  struct right_type< Head > {
    using type = Head;
  };
  template< typename ...Args >
  using right_type_t = typename right_type< Args... >::type;
}

#endif

