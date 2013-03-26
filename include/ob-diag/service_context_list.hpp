/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_SERVICE_CONTEXT_LIST_HPP
#define OB_DIAG_SERVICE_CONTEXT_LIST_HPP

#include <boost/fusion/include/vector.hpp>

#include <vector>

namespace ob_diag {

namespace fusion = boost::fusion;

typedef std::vector<fusion::vector2<unsigned int, std::vector<char> > > service_context_list;

}

#endif
