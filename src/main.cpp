/* (c) Copyright 2013 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#include <ob-diag/conditions.hpp>
#include <ob-diag/make_request.hpp>
#include <ob-diag/read_reply.hpp>
#include <ob-diag/create_session.hpp>
#include <ob-diag/signed_call_chain.hpp>
#include <ob-diag/search_offer.hpp>
#include <ob-diag/reference_types.hpp>
#include <ob-diag/properties_options.hpp>
#include <ob-diag/create_connection.hpp>
#include <ob-diag/make_call.hpp>

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

#include <boost/spirit/home/karma.hpp>
#include <boost/program_options.hpp>
#include <boost/asio.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/fusion/include/vector.hpp>
#include <boost/fusion/include/joint_view.hpp>
#include <boost/fusion/include/as_vector.hpp>
#include <boost/fusion/include/std_pair.hpp>
#include <boost/bind.hpp>

#include <openssl/rsa.h>
#include <openssl/pem.h>

namespace giop = morbid::giop;
namespace iiop = morbid::iiop;
namespace ior = morbid::ior;
namespace fusion = boost::fusion;
namespace mpl = boost::mpl;
namespace karma = boost::spirit::karma;
namespace qi = boost::spirit::qi;
namespace spirit = boost::spirit;
namespace phoenix = boost::phoenix;

using ob_diag::request_types;
using ob_diag::reply_types;

struct login_info
{
  std::string id, entity;
  unsigned int validity_time;
};

BOOST_FUSION_ADAPT_STRUCT(login_info, (std::string, id)(std::string, entity)
                          (unsigned int, validity_time));

void wait_bus_error(boost::system::error_code ec, std::size_t size, bool& read
                    , ob_diag::reference_connection& bus_connection)
{
  bool redo_connection = ec;
  assert(size == 0);
  OB_DIAG_ERR(ec, "Connection closed from bus. Reason: " << ec.message())
  read = true;

  if(!ec)
  {
    boost::asio::socket_base::bytes_readable command(true);
    bus_connection.socket->io_control(command);
    std::size_t bytes_readable = command.get();
    std::cout << "bytes readable " << bytes_readable << std::endl;
    OB_DIAG_ERR (bytes_readable == 0, "Connection was gracefully closed")
    if(bytes_readable == 0) redo_connection = true;
  }
  if(redo_connection)
  {
    std::cout << "Should redo connection to bus" << std::endl;
    OB_DIAG_FAIL (true, "Not implemented yet")
  }
}

 void wait_offer_error(boost::system::error_code ec, std::size_t size
                       , ob_diag::offer_info& oi
                       , std::vector<ob_diag::offer_info::offer>::iterator offer_iter
                       , ob_diag::reference_connection& bus_connection
                       , ob_diag::session& session)
{
  bool redo_connection = ec;
  assert(size == 0);
  OB_DIAG_ERR(ec, "Connection closed from offer. Reason: " << ec.message())

  if(!ec)
  {
    boost::asio::socket_base::bytes_readable command(true);
    offer_iter->ref_connection->socket->io_control(command);
    std::size_t bytes_readable = command.get();
    std::cout << "bytes readable " << bytes_readable << std::endl;
    OB_DIAG_ERR (bytes_readable == 0, "Connection was gracefully closed")
    if(bytes_readable == 0) redo_connection = true;
  }
  if(redo_connection)
  {
    std::cout << "Should redo connection" << std::endl;
    offer_iter->ref_connection = boost::none;
    offer_iter->offered_service_ref = boost::none;
    offer_iter->offer_properties.clear();
    offer_iter->offer_ref = boost::none;
  }
}

int main(int argc, char** argv)
{
  try
  {
    boost::program_options::options_description desc("Allowed options");
    std::string hostname;
    unsigned short port;

    {
      using boost::program_options::value;
      desc.add_options()
        ("help", "Shows this message")
        ("host,h", value<std::string>(&hostname), "Hostname of Openbus")
        ("port,p", value<unsigned short>(&port)->default_value(2089), "Port of Openbus (default: 2089)")
        ("username", value<std::string>(), "Username for authentication")
        ("password", value<std::string>(), "Password for authentatication")
        ("track-offer", value<std::vector<ob_diag::properties_options> >()
         , "List of name=value pairs of properties for tracking offers")
        ;
    }

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc)
                                , vm);
    boost::program_options::notify(vm);

    if(vm.count("help") || !vm.count("host"))
    {
      std::cout << desc << std::endl;
      return 1;
    }
    if((!vm.count("username") || !vm.count("password"))
       && vm.count("track-offer"))
    {
      std::cout << "If you use --track-offer option, you must offer credentials (--username/--password) for login" << std::endl;
      std::cout << desc << std::endl;
      return 1;
    }

    boost::asio::io_service io_service;
    ob_diag::reference_connection bus_connection;

    bus_connection.socket.reset(new boost::asio::ip::tcp::socket(io_service, boost::asio::ip::tcp::endpoint()));

    boost::system::error_code ec;

    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query
      (boost::asio::ip::tcp::endpoint::protocol_type::v4(), hostname, "");
    boost::asio::ip::tcp::resolver::iterator remote_iterator
      = resolver.resolve(query, ec);

    OB_DIAG_REQUIRE(!ec && remote_iterator != boost::asio::ip::tcp::resolver::iterator()
                    , "Resolving hostname was successful"
                    , "Resolving hostname failed with error: " << ec.message())

    boost::asio::ip::tcp::endpoint remote_endpoint = *remote_iterator;
    
    remote_endpoint.port(port);
    bus_connection.socket->connect(remote_endpoint, ec);

    OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of bus was successful"
                    , "Connection to hostname and port of bus failed with error: " << ec.message())

    {
      const char openbus_object_key_lit[] = "OpenBus_2_0";
      bus_connection.object_key.insert(bus_connection.object_key.end()
                                       , &openbus_object_key_lit[0]
                                       , &openbus_object_key_lit[0] + sizeof(openbus_object_key_lit)-1);
    }

    typedef std::vector<char>::iterator iterator_type;
    typedef ob_diag::reference_types<iterator_type> reference_types;
    typedef reference_types::reference_attribute_type arguments_attribute_type;

    reference_types reference_types_;
    arguments_attribute_type attr;

    ob_diag::make_call(bus_connection, "getFacet", giop::string
                       , fusion::make_vector
                       (std::string("IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0"))
                       , reference_types_.reference_grammar_, attr);

    OB_DIAG_REQUIRE((fusion::at_c<0u>(attr) == "IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0")
                    , "Found reference for AccessControl for OpenBus"
                    , "Expected reference for AccessControl, found instead reference to " << fusion::at_c<0u>(attr))

    ob_diag::reference_connection access_control_connection
      = ob_diag::create_connection_ref(fusion::at_c<1>(attr), io_service);

    boost::optional<ob_diag::session> session;
    std::vector<ob_diag::offer_info> tracking_offers;
    std::string busid;
    ob_diag::reference_connection offer_registry_connection;
    ::login_info login_info;
    EVP_PKEY* key = 0;
    if(vm.count("track-offer") > 0)
    {
      // Reading busid attribute
      ob_diag::make_call(access_control_connection
                         , "_get_busid", spirit::eps, fusion::vector0<>()
                         , giop::string, busid);

      // Reading buskey attribute
      typedef std::vector<unsigned char> buskey_args_type;
      buskey_args_type buskey_args;
      ob_diag::make_call(access_control_connection
                         , "_get_buskey", spirit::eps, fusion::vector0<>()
                         , giop::sequence[giop::octet], buskey_args);

      std::cout << "Returned encoded buskey public key with size " << buskey_args.size() << std::endl;

      EVP_PKEY* bus_key;
      {
        unsigned char const* buf = &buskey_args[0];
        bus_key = d2i_PUBKEY(0, &buf, buskey_args.size());
      }
      
      OB_DIAG_REQUIRE(bus_key != 0, "Read public key succesfully"
                      , "Reading public key failed. This is a bug in the diagnostic or a bug in OpenBus")

      {
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, 0);
        int r = EVP_PKEY_keygen_init(ctx);
        assert(r == 1);
        r = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
        assert(r == 1);
        r = EVP_PKEY_keygen(ctx, &key);
        assert((r == 1) && key);
      }
      
      std::string username = vm["username"].as<std::string>()
        , password = vm["password"].as<std::string>();

      std::vector<unsigned char> password_vector(password.begin(), password.end());
      std::vector<unsigned char> public_key_hash(32);
      std::vector<unsigned char> public_key_buffer;

      {
        unsigned char* key_buffer = 0;
        std::size_t len = i2d_PUBKEY(key, &key_buffer);
        SHA256(key_buffer, len, &public_key_hash[0]);
        public_key_buffer.insert(public_key_buffer.end(), key_buffer, key_buffer + len);
      }

      std::vector<unsigned char> encrypted_block;

      {
        std::vector<unsigned char> block;
        typedef giop::forward_back_insert_iterator<std::vector<unsigned char> > output_iterator_type;
        output_iterator_type iterator(block);
        bool g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                                 (giop::endianness(giop::native_endian)
                                  [+giop::octet & giop::sequence[giop::octet] ]
                                 )
                                 , fusion::make_vector(public_key_hash, password_vector));
      
        OB_DIAG_REQUIRE(g, "Generated buffer data to be transmitted encrypted to the Openbus " << block.size() << " bytes"
                        , "Failed generating buffer data to be encrypted. This is a bug in the diagnostic tool")

        {
          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(bus_key, 0);
          assert(!!ctx);
          int r = EVP_PKEY_encrypt_init(ctx);
          assert(r == 1);
          std::size_t encrypted_size = 0;
          r = EVP_PKEY_encrypt(ctx, 0, &encrypted_size, &block[0], block.size());
          assert(r == 1);
          encrypted_block.resize(encrypted_size);
          r = EVP_PKEY_encrypt(ctx, &encrypted_block[0], &encrypted_size
                               , &block[0], block.size());

          std::cout << "Encrypted Block size: " << encrypted_block.size() << std::endl;
        }
      }

      ob_diag::make_call(access_control_connection
                         , "loginByPassword"
                         , giop::string
                         & giop::sequence[giop::octet]
                         & +giop::octet
                         , fusion::make_vector(username, public_key_buffer, encrypted_block)
                         , giop::string & giop::string & giop::ulong_, login_info);

      std::cout << "Succesfully logged in. LoginInfo.id is " << login_info.id << std::endl;

      
      {
        reference_types reference_types_;
        arguments_attribute_type attr;

        ob_diag::make_call(bus_connection, "getFacet"
                           , giop::string
                           , fusion::make_vector
                           (std::string("IDL:tecgraf/openbus/core/v2_0/services/offer_registry/OfferRegistry:1.0"))
                           , reference_types_.reference_grammar_, attr);

        OB_DIAG_REQUIRE((fusion::at_c<0u>(attr) == "IDL:tecgraf/openbus/core/v2_0/services/offer_registry/OfferRegistry:1.0")
                        , "Found reference for OfferRegistry for OpenBus"
                        , "Expected reference for OfferRegistry, found instead reference to " << fusion::at_c<0u>(attr))

        offer_registry_connection = ob_diag::create_connection_ref(fusion::at_c<1>(attr), io_service);
      }

      std::vector<ob_diag::properties_options> search_tracking_offers
        = vm["track-offer"].as<std::vector<ob_diag::properties_options> >();
      tracking_offers.resize(search_tracking_offers.size());
      std::copy(search_tracking_offers.begin(), search_tracking_offers.end(), tracking_offers.begin());

      std::cout << "Tracking " << tracking_offers.size() << " offers" << std::endl;

      for(std::vector<ob_diag::offer_info>::iterator
            first = tracking_offers.begin()
            , last = tracking_offers.end()
            ;first != last; ++first)
      {
        if(!session)
          session = ob_diag::create_session
            (offer_registry_connection, "findServices"
             , giop::sequence[giop::string & giop::string]
             , fusion::vector1<std::vector<std::pair<std::string, std::string> > >()
             , busid, login_info.id, key);
        
        search_offer(access_control_connection, offer_registry_connection, io_service
                     , busid, *session, login_info.id, key, *first);
      }
    }

    std::cout << "will wait for any changes" << std::endl;
    bool bus_read = false;
    bus_connection.socket->async_read_some
      (boost::asio::null_buffers()
       , boost::bind(wait_bus_error, _1, _2, boost::ref(bus_read), boost::ref(bus_connection)));

    for(std::vector<ob_diag::offer_info>::iterator offer_first = tracking_offers.begin()
          , offer_last = tracking_offers.end()
          ; offer_first != offer_last; ++offer_first)
    {
      for(std::vector<ob_diag::offer_info::offer>::iterator
            first = offer_first->offers.begin()
            , last = offer_first->offers.end()
            ;first != last;++first)
      {
        assert(!!session);
        if(first->ref_connection)
          first->ref_connection->socket->async_read_some
            (boost::asio::null_buffers()
             , boost::bind(wait_offer_error, _1, _2, boost::ref(*offer_first)
                           , boost::ref(first)
                           , boost::ref(bus_connection), boost::ref(*session)));
      }
    }

    do
    {

      boost::asio::steady_timer timer(io_service, boost::chrono::seconds(5));
      
      timer.async_wait(boost::bind(&boost::asio::io_service::stop, boost::ref(io_service)));

      io_service.run();
      io_service.reset();
      std::cout << "Waited" << std::endl;

      for(std::vector<ob_diag::offer_info>::iterator offer_first = tracking_offers.begin()
            , offer_last = tracking_offers.end()
            ; offer_first != offer_last; ++offer_first)
      {
        if(offer_first->offers.empty() || !offer_first->offers[0].ref_connection)
        {
          std::cout << "Search again" << std::endl;
          
          search_offer(access_control_connection, offer_registry_connection, io_service
                       , busid, *session, login_info.id, key, *offer_first);
        }
      }

      if(bus_read)
      {
        bus_read = false;
        bus_connection.socket->async_read_some
          (boost::asio::null_buffers()
           , boost::bind(wait_bus_error, _1, _2, boost::ref(bus_read)
                         , boost::ref(bus_connection)));
      }
    }
    while(true);
  }
  catch(ob_diag::require_error const&)
  {
  }
}
