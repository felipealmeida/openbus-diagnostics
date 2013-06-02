/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_MAKE_REQUEST_HPP
#define OB_DIAG_MAKE_REQUEST_HPP

#include <ob-diag/service_context_list.hpp>
#include <ob-diag/session.hpp>
#include <ob-diag/reference_connection.hpp>

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

#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

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
  request_types<Args> rt (args_grammar, object_key, method, args, service_context);
      
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

  OB_DIAG_REQUIRE(!ec, "Sent buffer with request for operation " << method
                  , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())
}

template <typename ArgsGrammar, typename Args>
void make_openbus_request(boost::asio::ip::tcp::socket& socket
                          , std::vector<char> const& object_key
                          , std::string const& method
                          , ArgsGrammar const& args_grammar
                          , Args const& args
                          , std::string bus_id
                          , std::string local_id
                          , session& s
                          , fusion::vector2<std::vector<unsigned char>, std::vector<unsigned char> > signed_call_chain
                          = fusion::vector2<std::vector<unsigned char>, std::vector<unsigned char> >
                          (std::vector<unsigned char>(256u), std::vector<unsigned char>()))
{
  assert(s.secret.size() == 16u);

  std::vector<char> hash(32u);
  {
    std::vector<char> buffer;
    std::back_insert_iterator<std::vector<char> > iterator(buffer);
    bool g = karma::generate
      (iterator
       ,  qi::char_
       << qi::char_
       << spirit::repeat(16u)[qi::char_]
       << qi::little_dword
       << qi::string
       , fusion::make_vector(2, 0, s.secret, s.ticket, method));

    OB_DIAG_REQUIRE(g, "Generated buffer for hashing for " << method << " with established session"
                    , "Failed generating buffer for hashing for call to " << method
                    << " with established session. This is a bug in the diagnostic tool")

    assert(buffer.size() == 22 + method.size());
    SHA256((unsigned char*)&buffer[0], buffer.size(), (unsigned char*)&hash[0]);
  }

  std::vector<char> credential_data;
  giop::forward_back_insert_iterator<std::vector<char> > iterator(credential_data);
  bool g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                           (
                            giop::endianness(giop::native_endian)
                            [
                             giop::string & giop::string
                             & giop::ulong_ & giop::ulong_
                             & +giop::octet
                             // Signed Call Chain
                             & +giop::octet
                             & giop::sequence[giop::octet]
                            ]
                           )
                           , fusion::make_vector
                           (bus_id, local_id, s.session_number
                            , s.ticket, hash
                            // Signed Call Chain
                            , fusion::at_c<0u>(signed_call_chain), fusion::at_c<1u>(signed_call_chain)));

  OB_DIAG_REQUIRE(g, "Generated service context for call to " << method << " with established session"
                  , "Failed generating context for call to " << method
                  << " with established session. This is a bug in the diagnostic tool")

  ++s.ticket;

  ob_diag::service_context_list service_context;
  service_context.push_back
    (fusion::make_vector(0x42555300, credential_data)); 
  make_request(socket, object_key, method, args_grammar, args, service_context);
}

template <typename ArgsGrammar, typename Args>
void make_request(reference_connection const& ref_c
                  , std::string const& method
                  , ArgsGrammar const& args_grammar
                  , Args const& args
                  , service_context_list const& service_context = service_context_list())
{
  make_request(*ref_c.socket, ref_c.object_key, method, args_grammar, args, service_context);
}

template <typename ArgsGrammar, typename Args>
void make_openbus_request(reference_connection const& ref_c
                          , std::string const& method
                          , ArgsGrammar const& args_grammar
                          , Args const& args
                          , std::string bus_id
                          , std::string local_id
                          , session& s
                          , fusion::vector2<std::vector<unsigned char>, std::vector<unsigned char> > signed_call_chain
                          = fusion::vector2<std::vector<unsigned char>, std::vector<unsigned char> >
                          (std::vector<unsigned char>(256u), std::vector<unsigned char>()))
{
  make_openbus_request(*ref_c.socket, ref_c.object_key, method, args_grammar, args, bus_id
                       , local_id, s, signed_call_chain);
}

}

#endif
