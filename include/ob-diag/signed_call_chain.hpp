/* (c) Copyright 2013 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_SIGNED_CALL_CHAIN_HPP
#define OB_DIAG_SIGNED_CALL_CHAIN_HPP

#include <boost/fusion/include/adapt_struct.hpp>

#include <vector>

namespace ob_diag {

namespace fusion = boost::fusion;

struct signed_call_chain
{
  std::vector<unsigned char> signature, encoded;
};

}

BOOST_FUSION_ADAPT_STRUCT(ob_diag::signed_call_chain
                          , (std::vector<unsigned char>, signature)(std::vector<unsigned char>, encoded));

#endif
