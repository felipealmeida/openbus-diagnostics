/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_SYSTEM_EXCEPTION_HPP
#define OB_DIAG_SYSTEM_EXCEPTION_HPP

#include <boost/integer.hpp>

#include <vector>
#include <string>

namespace ob_diag {

struct system_exception
{
  std::string exception_id;
  unsigned int minor_code_value, completion_status;
};

}

BOOST_FUSION_ADAPT_STRUCT(ob_diag::system_exception
                          , (std::string, exception_id)
                            (unsigned int, minor_code_value)
                            (unsigned int, completion_status));


#endif
