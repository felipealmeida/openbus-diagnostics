/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_REFERENCE_TYPES_HPP
#define OB_DIAG_REFERENCE_TYPES_HPP

#include <morbid/giop/forward_back_insert_iterator.hpp>
#include <morbid/giop/grammars/arguments.hpp>
#include <morbid/giop/grammars/message_1_0.hpp>
#include <morbid/giop/grammars/request_1_0.hpp>
#include <morbid/giop/grammars/reply_1_0.hpp>
#include <morbid/giop/grammars/system_exception_reply_body.hpp>
#include <morbid/iiop/all.hpp>
#include <morbid/iiop/grammars/profile_body_1_1.hpp>
#include <morbid/iiop/profile_body.hpp>

#include <morbid/ior/grammar/generic_tagged_profile.hpp>
#include <morbid/ior/grammar/tagged_profile.hpp>
#include <morbid/ior/grammar/ior.hpp>
#include <morbid/ior/tagged_profile.hpp>

namespace ob_diag {

namespace ior = morbid::ior;
namespace iiop = morbid::iiop;
namespace giop = morbid::giop;

template <typename Iterator>
struct reference_types
{
  typedef typename fusion::result_of::as_vector
  <fusion::joint_view<fusion::single_view<char> // minor version
                      , iiop::profile_body> >::type profile_body_1_1_attr;

  ior::grammar::tagged_profile<iiop::parser_domain, Iterator
                               , ior::tagged_profile> tagged_profile;
  iiop::grammar::profile_body_1_0<iiop::parser_domain, Iterator
                                  , iiop::profile_body> profile_body_1_0;
  iiop::grammar::profile_body_1_1<iiop::parser_domain, Iterator
                                  , profile_body_1_1_attr> profile_body_1_1;
  ior::grammar::generic_tagged_profile<iiop::parser_domain, Iterator
                                       , boost::variant<iiop::profile_body, profile_body_1_1_attr>, 0u
                                       > tagged_profile_body;


  typedef fusion::vector2<std::string
                          , std::vector
                          <boost::variant<iiop::profile_body, profile_body_1_1_attr, ior::tagged_profile> >
                          > reference_attribute_type;

  typedef ior::grammar::ior<iiop::parser_domain, Iterator
                            , reference_attribute_type>
    reference_grammar;

  reference_grammar reference_grammar_;

  reference_types()
    : tagged_profile_body(giop::endianness[profile_body_1_0 | profile_body_1_1])
    , reference_grammar_(tagged_profile_body | tagged_profile)
  {}
};

}

#endif
