/* (c) Copyright 2013 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_READ_REPLY_HPP
#define OB_DIAG_READ_REPLY_HPP

#include <ob-diag/service_context_list.hpp>
#include <ob-diag/system_exception.hpp>
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
struct reply_types
{
  typedef std::vector<char>::iterator iterator_type;
  typedef boost::variant<system_exception, user_exception, A> variant_attribute_type;

  typedef fusion::vector4<service_context_list, unsigned int, unsigned int
                          , variant_attribute_type>
    reply_attribute_type;
  typedef fusion::vector1<reply_attribute_type>
    message_attribute_type;
  typedef giop::grammars::system_exception_reply_body
    <iiop::parser_domain, iterator_type, system_exception>
    system_exception_grammar;
  typedef giop::grammars::reply_1_0<iiop::parser_domain
                                    , iterator_type, reply_attribute_type>
    reply_grammar;
  typedef giop::grammars::message_1_0
    <iiop::parser_domain
     , iterator_type, message_attribute_type, 1u /* Reply */>
    message_grammar;
  system_exception_grammar system_exception_grammar_;

  reply_grammar reply_grammar_;

  message_grammar message_grammar_;
  message_attribute_type attribute;

  template <typename U>
  reply_types(U const& args_grammar)
    : reply_grammar_
      (
       (
        spirit::eps(phoenix::at_c<2u>(spirit::_val) == 0u)
        & args_grammar
       ) |
       (
        spirit::eps(phoenix::at_c<2u>(spirit::_val) == 1u)
        & spirit::attr_cast<user_exception>(giop::string)
       ) |
       (
        spirit::eps(phoenix::at_c<2u>(spirit::_val) == 2u)
        & system_exception_grammar_
       )
      )
    , message_grammar_(reply_grammar_)
  {}  
};

template <typename OutGrammar, typename Out>
void read_reply(boost::asio::ip::tcp::socket& socket
                , OutGrammar const& out_grammar
                , Out& out
                //                , service_context_list&)
                )
{
  std::vector<char> reply_buffer(1024*1024);
  std::size_t offset = 0, size_to_download = 0;
  typedef std::vector<char>::iterator iterator_type;
  iterator_type first;
  bool header_parse = false;

  do
  {
    boost::system::error_code ec;
    std::size_t bytes_read = socket.read_some
      (boost::asio::mutable_buffers_1(&reply_buffer[offset], reply_buffer.size() - offset), ec);
    offset += bytes_read;

    OB_DIAG_REQUIRE(!ec, "Read  " << offset << " bytes"
                    ,  "Failed reading with error " << ec.message())

    if(offset > 12)
    {
      first = reply_buffer.begin();
      fusion::vector2<unsigned char, unsigned int> attribute;
      header_parse = qi::parse(first, reply_buffer.begin() + offset
                               , giop::compile<iiop::parser_domain>
                               ("GIOP"
                                & giop::octet('\1')
                                & giop::octet('\0')
                                & giop::endianness
                                [
                                 giop::octet
                                 & giop::ulong_
                                ]
                               )
                               , attribute);
      unsigned char message_type = fusion::at_c<0>(attribute);
      size_to_download = fusion::at_c<1>(attribute);
      OB_DIAG_FAIL(!header_parse, "Garbage was received as reply or a bug in the diagnostic tool")
      OB_DIAG_FAIL(message_type != 1, "Message type " << message_type << " was not expected. Expected a GIOP reply message."
                   " This might be a bug in the diagnostic tool")
      OB_DIAG_FAIL(std::distance(reply_buffer.begin(), first) + size_to_download > reply_buffer.size()
                   , "Message is bigger than 1MB, higher than the limit for the diagnostic tool")
      OB_DIAG_FAIL(std::distance(first, reply_buffer.begin() + offset) > size_to_download
                   , "Received more data than was expected or a bug in the diagnostic tool")
    }
  }
  while(offset <= 12 
        || std::distance(first, reply_buffer.begin() + offset) != size_to_download);

  reply_buffer.resize(offset);

  first = reply_buffer.begin();
  iterator_type last = reply_buffer.end();

  typedef reply_types<Out> reply_type;
  reply_type reply(out_grammar);

  bool g = qi::parse(first, last
                     , giop::compile<iiop::parser_domain>
                     (reply.message_grammar_)
                     , reply.attribute)
    && first == last;
  
  OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                  , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

  typename reply_type::variant_attribute_type variant_attr
    = fusion::at_c<3u>(fusion::at_c<0u>(reply.attribute));

  OB_DIAG_FAIL(system_exception* e = boost::get<system_exception>(&variant_attr)
               , "A system exception was thrown! " << e->exception_id << " with minor code: " << e->minor_code_value)
  OB_DIAG_FAIL(user_exception* e = boost::get<user_exception>(&variant_attr)
               , "A user exception was thrown! " << e->exception_id)

  out = boost::get<Out>(variant_attr);
}

template <typename OutGrammar, typename Out>
void read_reply(reference_connection const& ref_c
                , OutGrammar const& out_grammar
                , Out& out)
{
  read_reply(*ref_c.socket, out_grammar, out);
}

}

#endif
