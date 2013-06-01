/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_CREATE_CONNECTION_HPP
#define OB_DIAG_CREATE_CONNECTION_HPP

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
                  , "Connection to hostname and port of IIOP Profile was succesful failed with error " << ec.message())

  return socket;
}

}

#endif
