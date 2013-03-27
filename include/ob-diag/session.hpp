/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_SESSION_HPP
#define OB_DIAG_SESSION_HPP

#include <boost/integer.hpp>

#include <vector>
#include <string>

namespace ob_diag {

struct session
{
  session(std::string const& remote_id
          , boost::uint_t<32u>::least session_number
          , std::vector<char> secret)
    : remote_id(remote_id), session_number(session_number)
    , secret(secret), ticket(0u) {}

  std::string remote_id;
  boost::uint_t<32u>::least session_number;
  std::vector<char> secret;
  boost::uint_t<32>::exact ticket;
};

}

#endif
