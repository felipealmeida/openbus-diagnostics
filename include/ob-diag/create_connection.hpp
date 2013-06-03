/* (c) Copyright 2013 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_CREATE_CONNECTION_HPP
#define OB_DIAG_CREATE_CONNECTION_HPP

#include <ob-diag/reference_types.hpp>
#include <ob-diag/reference_connection.hpp>

#include <boost/asio.hpp>

namespace ob_diag {

boost::shared_ptr<boost::asio::ip::tcp::socket> create_connection(std::string const& hostname, unsigned short port
                                                                  ,   boost::asio::io_service& io_service)
{
  boost::shared_ptr<boost::asio::ip::tcp::socket>
    socket(new boost::asio::ip::tcp::socket(io_service, boost::asio::ip::tcp::endpoint()));

  std::cout << "Hostname: " << hostname
            << " Port: " << port << std::endl;
        
  boost::asio::ip::tcp::resolver resolver(io_service);
  boost::asio::ip::tcp::resolver::query query
    (boost::asio::ip::tcp::endpoint::protocol_type::v4(), hostname, "");
  boost::system::error_code ec;
  boost::asio::ip::tcp::resolver::iterator remote_iterator
    = resolver.resolve(query, ec);

  OB_DIAG_REQUIRE(remote_iterator != boost::asio::ip::tcp::resolver::iterator()
                  , "Succesful querying hostname(" << hostname << ") from IIOP Profile"
                  , "Querying hostname(" << hostname << ") from IIOP Profile failed with error " << ec.message() << ". Check /etc/hosts in the server for any misconfigured hostnames")

  boost::asio::ip::tcp::endpoint remote_endpoint = *remote_iterator;
  remote_endpoint.port(port);

  socket->connect(remote_endpoint, ec);

  OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of IIOP Profile was succesful"
                  , "Connection to hostname and port of IIOP Profile failed with error " << ec.message())

  return socket;
}

template <typename V>
boost::optional<reference_connection> create_connection_from_seq(V const& v, boost::asio::io_service& io_service)
{
  try
  {
    boost::shared_ptr<boost::asio::ip::tcp::socket> socket
      = create_connection(fusion::at_c<0u>(v), fusion::at_c<1u>(v), io_service);
    reference_connection r = { socket, fusion::at_c<2u>(v) };
    return r;
  }
  catch(ob_diag::require_error const&)
  {
    OB_DIAG_ERR(true, "Connection to profile in IIOP failed")
  }
  return boost::none;
}

namespace ior = morbid::ior;
namespace iiop = morbid::iiop;

typedef std::vector<boost::variant<iiop::profile_body, reference_types<std::vector<char>::iterator>::profile_body_1_1_attr
                                   , ior::tagged_profile> > profiles_type;

reference_connection create_connection_ref(profiles_type const& profiles, boost::asio::io_service& io_service)
{
  typedef ob_diag::reference_types<std::vector<char>::iterator> reference_types;
  bool has_iiop_profile = false;
  reference_connection ref_connection;
  for(profiles_type::const_iterator profile_first = profiles.begin()
        , profile_last = profiles.end()
        ; profile_first != profile_last; ++profile_first)
  {
    if(iiop::profile_body const* p = boost::get<iiop::profile_body>(&*profile_first))
    {
      std::cout << "IIOP Profile Body" << std::endl;
      if(boost::optional<reference_connection> r = create_connection_from_seq(*p , io_service))
        if(!ref_connection.socket)
          ref_connection = *r;
      has_iiop_profile = true;
    }
    else if(reference_types::profile_body_1_1_attr const* p
            = boost::get<reference_types::profile_body_1_1_attr>(&*profile_first))
    {
      std::cout << "IIOP Profile Body 1." << (int)fusion::at_c<0u>(*p) << std::endl;
      if(boost::optional<reference_connection> r
         = create_connection_from_seq(boost::fusion::pop_front(*p), io_service))
        if(!ref_connection.socket)
          ref_connection = *r;
      has_iiop_profile = true;
    }
    else
    {
      std::cout << "Other Tagged Profiles" << std::endl;
    }
  }

  OB_DIAG_FAIL(!ref_connection.socket, "No reachable IIOP profile. Service might be down")
  OB_DIAG_FAIL(!has_iiop_profile, "No IIOP profile. This is a bug in the diagnostic or a bug in the service")

  return ref_connection;
}

}

#endif
