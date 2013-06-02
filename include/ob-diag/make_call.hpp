/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_MAKE_CALL_HPP
#define OB_DIAG_MAKE_CALL_HPP

#include <ob-diag/make_request.hpp>
#include <ob-diag/read_reply.hpp>
#include <ob-diag/reference_connection.hpp>

namespace ob_diag {

template <typename ArgsGrammar, typename Args, typename OutGrammar, typename Out>
void make_call(boost::asio::ip::tcp::socket& socket
               , std::vector<char> const& object_key
               , std::string const& method
               , ArgsGrammar const& args_grammar
               , Args const& args
               , OutGrammar const& out_grammar
               , Out& out
               , service_context_list const& service_context = service_context_list())
{
  ob_diag::make_request(socket, object_key, method
                        , args_grammar
                        , args
                        , service_context);
  ob_diag::read_reply(socket, out_grammar, out);
}

template <typename ArgsGrammar, typename Args, typename OutGrammar, typename Out>
void make_call(reference_connection const& ref_c
               , std::string const& method
               , ArgsGrammar const& args_grammar
               , Args const& args
               , OutGrammar const& out_grammar
               , Out& out
               , service_context_list const& service_context = service_context_list())
{
  make_call(*ref_c.socket, ref_c.object_key, method, args_grammar, args, out_grammar
            , out, service_context);
}

template <typename ArgsGrammar, typename Args, typename OutGrammar, typename Out>
void make_openbus_call(reference_connection const& ref_c
                       , std::string const& method
                       , ArgsGrammar const& args_grammar
                       , Args const& args
                       , OutGrammar const& out_grammar
                       , Out& out
                       , session& remote_session
                       , reference_connection const& acs_connection
                       , std::string const& bus_id
                       , std::string const& local_id
                       , session& bus_session)
{
  make_openbus_request(acs_connection, "signChainFor"
                       , giop::string, fusion::make_vector(remote_session.remote_id)
                       , bus_id, local_id, bus_session);
  fusion::vector2<std::vector<unsigned char>, std::vector<unsigned char> > signed_call_chain;
  read_reply(acs_connection
             , spirit::repeat(256u)[giop::octet]
             & giop::sequence[giop::octet]
             , signed_call_chain);

  ob_diag::make_openbus_request(ref_c, method, args_grammar, args, bus_id, local_id, remote_session, signed_call_chain);
  ob_diag::read_reply(ref_c, out_grammar, out);
}

}

#endif
