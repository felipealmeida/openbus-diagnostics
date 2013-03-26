/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_MAKE_REQUEST_HPP
#define OB_DIAG_MAKE_REQUEST_HPP

#include <ob-diag/service_context_list.hpp>

#include <morbid/giop/forward_back_insert_iterator.hpp>
#include <morbid/giop/grammars/arguments.hpp>
#include <morbid/giop/grammars/message_1_0.hpp>
#include <morbid/giop/grammars/request_1_0.hpp>
#include <morbid/giop/grammars/reply_1_0.hpp>
#include <morbid/giop/grammars/system_exception_reply_body.hpp>
#include <morbid/iiop/all.hpp>
#include <morbid/iiop/grammars/profile_body_1_1.hpp>
#include <morbid/iiop/profile_body.hpp>

#include <boost/asio.hpp>

namespace ob_diag {

namespace giop = morbid::giop;
namespace iiop = morbid::iiop;
namespace fusion = boost::fusion;
namespace mpl = boost::mpl;
namespace karma = boost::spirit::karma;
namespace qi = boost::spirit::qi;
namespace spirit = boost::spirit;
namespace phoenix = boost::phoenix;

template <typename A>
struct request_types
{
  typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;

  typedef fusion::vector6<service_context_list
                          , unsigned int, bool, std::vector<char>, std::string
                          , std::vector<char> >
    request_grammar_attribute_type;
  typedef fusion::joint_view
    <request_grammar_attribute_type
     , A> request_attribute_type;
  typedef fusion::vector1<request_attribute_type>
    message_attribute_type;

  typedef giop::grammars::request_1_0<iiop::generator_domain
                                      , output_iterator_type, request_attribute_type>
    request_header_grammar;
  typedef giop::grammars::message_1_0<iiop::generator_domain
                                      , output_iterator_type, message_attribute_type
                                      , 0u /* request */>
    message_header_grammar;

  request_header_grammar request_header_grammar_;
  message_header_grammar message_header_grammar_;
  request_grammar_attribute_type request_grammar_attribute;
  A args;
  message_attribute_type attribute;

  template <typename G>
  request_types(G g, std::vector<char> const& object_key, std::string const& method, A const& args
                , service_context_list const& service_context = service_context_list())
    : request_header_grammar_(g)
    , message_header_grammar_(request_header_grammar_)
    , request_grammar_attribute(service_context, 1u, true, object_key
                                , method, std::vector<char>()
                                )
    , args(args)
    , attribute(request_attribute_type(request_grammar_attribute, this->args))
  {
  }
};

template <typename ArgsGrammar, typename Args>
void make_request(boost::asio::ip::tcp::socket& socket
                  , std::vector<char> const& object_key
                  , std::string const& method
                  , ArgsGrammar const& args_grammar
                  , Args const& args
                  , service_context_list const& service_context = service_context_list())
{
  typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
  request_types<Args> rt (args_grammar, object_key, method, args);
      
  std::vector<char> buffer;
  output_iterator_type iterator(buffer);
  bool g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                           (rt.message_header_grammar_(giop::native_endian))
                           , rt.attribute);

  OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                  , "Failed generating request. This is a bug in the diagnostic tool")

  boost::system::error_code ec;
  boost::asio::write(socket, boost::asio::buffer(buffer)
                     , boost::asio::transfer_all(), ec);

  OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                  , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())
}

}

#endif
