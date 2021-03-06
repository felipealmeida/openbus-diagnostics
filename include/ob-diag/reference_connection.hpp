/* (c) Copyright 2013 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_REFERENCE_CONNECTION_HPP
#define OB_DIAG_REFERENCE_CONNECTION_HPP

#include <boost/shared_ptr.hpp>
#include <boost/asio.hpp>

#include <vector>

namespace ob_diag {

struct reference_connection
{
  boost::shared_ptr<boost::asio::ip::tcp::socket> socket;
  std::vector<char> object_key;
};

inline bool operator==(reference_connection const& lhs, reference_connection const& rhs)
{
  return lhs.socket == rhs.socket && lhs.object_key == rhs.object_key;
}

}

#endif
