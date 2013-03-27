/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#include <ob-diag/conditions.hpp>
#include <ob-diag/make_request.hpp>
#include <ob-diag/read_reply.hpp>
#include <ob-diag/signed_call_chain.hpp>

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
#include <boost/fusion/include/vector.hpp>
#include <boost/fusion/include/joint_view.hpp>
#include <boost/fusion/include/as_vector.hpp>

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

void profile_body_test(std::string const& hostname, unsigned short port)
{
  boost::asio::io_service io_service;
  boost::asio::ip::tcp::socket socket(io_service, boost::asio::ip::tcp::endpoint());

  std::cout << "Hostname: " << hostname
            << " Port: " << port << std::endl;
        
  boost::asio::ip::tcp::resolver resolver(io_service);
  boost::asio::ip::tcp::resolver::query query
    (boost::asio::ip::tcp::endpoint::protocol_type::v4(), hostname, "");
  boost::system::error_code ec;
  boost::asio::ip::tcp::endpoint remote_endpoint = *resolver.resolve(query, ec);
  remote_endpoint.port(port);

  OB_DIAG_REQUIRE(!ec, "Succesful querying hostname(" << hostname << ") from IIOP Profile"
                  , "Querying hostname(" << hostname << ") from IIOP Profile failed with error " << ec.message() << ". Check /etc/hosts in the server for any misconfigured hostnames")

  socket.connect(remote_endpoint, ec);

  OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of IIOP Profile was succesful"
                  , "Connection to hostname and port of IIOP Profile was succesful failed with error " << ec.message())
}

struct login_info
{
  std::string id, entity;
  unsigned int validity_time;
};

BOOST_FUSION_ADAPT_STRUCT(login_info, (std::string, id)(std::string, entity)
                          (unsigned int, validity_time));

int main(int argc, char** argv)
{
  try
  {
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
      ("help", "Shows this message")
      ("host,h", boost::program_options::value<std::string>(), "Hostname of Openbus")
      ("port,p", boost::program_options::value<unsigned short>(), "Port of Openbus")
      ("username", boost::program_options::value<std::string>(), "Username for authentication")
      ("password", boost::program_options::value<std::string>(), "Password for authentatication")
      ;

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc)
                                , vm);
    boost::program_options::notify(vm);

    if(vm.count("help") || !vm.count("host")
       || !vm.count("port") || !vm.count("username")
       || !vm.count("password"))
    {
      std::cout << desc << std::endl;
      return 1;
    }

    std::string hostname = vm["host"].as<std::string>();
    unsigned short port = vm["port"].as<unsigned short>();
    std::string username = vm["username"].as<std::string>()
      , password = vm["password"].as<std::string>();

    boost::asio::io_service io_service;
    boost::asio::ip::tcp::socket socket(io_service, boost::asio::ip::tcp::endpoint());

    boost::system::error_code ec;

    boost::asio::ip::tcp::resolver resolver(io_service);
    boost::asio::ip::tcp::resolver::query query
      (boost::asio::ip::tcp::endpoint::protocol_type::v4(), hostname, "");
    boost::asio::ip::tcp::endpoint remote_endpoint = *resolver.resolve(query, ec);

    OB_DIAG_REQUIRE(!ec, "Resolving hostname was successful"
                    , "Resolving hostname failed with error: " << ec.message())
    
    remote_endpoint.port(port);
    socket.connect(remote_endpoint, ec);

    OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of bus was successful"
                    , "Connection to hostname and port of bus failed with error: " << ec.message())
                    
    std::vector<char> openbus_object_key;
    {
      const char openbus_object_key_lit[] = "OpenBus_2_0";
      openbus_object_key.insert(openbus_object_key.end(), &openbus_object_key_lit[0]
                                , &openbus_object_key_lit[0] + sizeof(openbus_object_key_lit)-1);
    }

    ob_diag::make_request(socket, openbus_object_key, "getFacet"
                          , giop::string
                          , fusion::make_vector
                          (std::string("IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0")));

    typedef std::vector<char>::iterator iterator_type;
    typedef ::reference_types<iterator_type> reference_types;
    reference_types reference_types_;
    typedef reference_types::reference_attribute_type arguments_attribute_type;

    arguments_attribute_type attr;
    ob_diag::read_reply(socket, reference_types_.reference_grammar_, attr);

    OB_DIAG_REQUIRE((fusion::at_c<0u>(attr) == "IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0")
                    , "Found reference for AccessControl for OpenBus"
                    , "Expected reference for AccessControl, found instead reference to " << fusion::at_c<0u>(attr))

    bool has_iiop_profile = false;
    std::vector<char> access_control_object_key;

    typedef std::vector
      <boost::variant<iiop::profile_body, reference_types::profile_body_1_1_attr
                      , ior::tagged_profile> > profiles_type;
    for(profiles_type::const_iterator first = fusion::at_c<1u>(attr).begin()
          , last = fusion::at_c<1u>(attr).end(); first != last; ++first)
    {
      if(iiop::profile_body const* p = boost::get<iiop::profile_body>(&*first))
      {
        std::cout << "IIOP Profile Body" << std::endl;
        profile_body_test(fusion::at_c<0u>(*p), fusion::at_c<1u>(*p));
        if(access_control_object_key.empty())
          access_control_object_key = fusion::at_c<2u>(*p);
        has_iiop_profile = true;
      }
      else if(reference_types::profile_body_1_1_attr const* p
              = boost::get<reference_types::profile_body_1_1_attr>(&*first))
      {
        std::cout << "IIOP Profile Body 1." << (int)fusion::at_c<0u>(*p) << std::endl;
        profile_body_test(fusion::at_c<1u>(*p), fusion::at_c<2u>(*p));
        if(access_control_object_key.empty())
          access_control_object_key = fusion::at_c<3u>(*p);
        has_iiop_profile = true;
      }
      else
      {
        std::cout << "Other Tagged Profiles" << std::endl;
      }
    }

    OB_DIAG_FAIL(!has_iiop_profile, "IOR has no IIOP Profile bodies. Can't communicate with TCP")

    OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of bus was successful"
                    , "Connection to hostname and port of bus failed with error: " << ec.message())

    std::string busid;
    std::vector<char> buffer;
    typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
    output_iterator_type iterator(buffer);
    std::vector<char> reply_buffer;
    iterator_type first, last;
    std::size_t size;
    bool g;

    // Reading busid attribute
    ob_diag::make_request(socket, access_control_object_key
                          , "_get_busid", spirit::eps, fusion::vector0<>());

    ob_diag::read_reply(socket, giop::string, busid);

    // Reading buskey attribute
    ob_diag::make_request(socket, access_control_object_key
                          , "_get_buskey", spirit::eps, fusion::vector0<>());

    typedef std::vector<unsigned char> buskey_args_type;
    buskey_args_type buskey_args;
    ob_diag::read_reply(socket, giop::sequence[giop::octet], buskey_args);

    std::cout << "Returned encoded buskey public key with size " << buskey_args.size() << std::endl;

    EVP_PKEY* bus_key;
    {
      unsigned char const* buf = &buskey_args[0];
      bus_key = d2i_PUBKEY(0, &buf, buskey_args.size());
    }

    OB_DIAG_REQUIRE(bus_key != 0, "Read public key succesfully"
                    , "Reading public key failed. This is a bug in the diagnostic or a bug in OpenBus")

    EVP_PKEY* key = 0;
    {
      EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, 0);
      int r = EVP_PKEY_keygen_init(ctx);
      assert(r == 1);
      r = EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
      assert(r == 1);
      r = EVP_PKEY_keygen(ctx, &key);
      assert((r == 1) && key);
    }
      
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
      g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                          (giop::endianness(giop::native_endian)
                           [+giop::octet & giop::sequence[giop::octet]
                           ]
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

    ob_diag::make_request(socket, access_control_object_key
                          , "loginByPassword"
                          , giop::string
                          & giop::sequence[giop::octet]
                          & +giop::octet
                          , fusion::make_vector(username, public_key_buffer, encrypted_block));

    ::login_info login_info;
    ob_diag::read_reply(socket, giop::string & giop::string & giop::ulong_, login_info);

    std::cout << "Succesfully logged in. LoginInfo.id is " << login_info.id << std::endl;

    std::vector<char> offer_registry_object_key;

    {
      ob_diag::make_request(socket, openbus_object_key, "getFacet"
                            , giop::string
                            , fusion::make_vector
                            (std::string("IDL:tecgraf/openbus/core/v2_0/services/offer_registry/OfferRegistry:1.0")));

      typedef std::vector<char>::iterator iterator_type;
      typedef ::reference_types<iterator_type> reference_types;
      reference_types reference_types_;
      typedef reference_types::reference_attribute_type arguments_attribute_type;

      arguments_attribute_type attr;
      ob_diag::read_reply(socket, reference_types_.reference_grammar_, attr);

      OB_DIAG_REQUIRE((fusion::at_c<0u>(attr) == "IDL:tecgraf/openbus/core/v2_0/services/offer_registry/OfferRegistry:1.0")
                      , "Found reference for OfferRegistry for OpenBus"
                      , "Expected reference for OfferRegistry, found instead reference to " << fusion::at_c<0u>(attr))

      bool has_iiop_profile = false;
      typedef std::vector
        <boost::variant<iiop::profile_body, reference_types::profile_body_1_1_attr
                        , ior::tagged_profile> > profiles_type;
      for(profiles_type::const_iterator first = fusion::at_c<1u>(attr).begin()
            , last = fusion::at_c<1u>(attr).end(); first != last; ++first)
      {
        if(iiop::profile_body const* p = boost::get<iiop::profile_body>(&*first))
        {
          std::cout << "IIOP Profile Body" << std::endl;
          profile_body_test(fusion::at_c<0u>(*p), fusion::at_c<1u>(*p));
          if(offer_registry_object_key.empty())
            offer_registry_object_key = fusion::at_c<2u>(*p);
          has_iiop_profile = true;
        }
        else if(reference_types::profile_body_1_1_attr const* p
                = boost::get<reference_types::profile_body_1_1_attr>(&*first))
        {
          std::cout << "IIOP Profile Body 1." << (int)fusion::at_c<0u>(*p) << std::endl;
          profile_body_test(fusion::at_c<1u>(*p), fusion::at_c<2u>(*p));
          if(offer_registry_object_key.empty())
            offer_registry_object_key = fusion::at_c<3u>(*p);
          has_iiop_profile = true;
        }
        else
        {
          std::cout << "Other Tagged Profiles" << std::endl;
        }
      }

      OB_DIAG_FAIL(!has_iiop_profile, "IOR has no IIOP Profile bodies. Can't communicate with TCP")
    }

    std::vector<char> empty_credential_data;
    {
      output_iterator_type iterator(empty_credential_data);
      g = karma::generate(iterator, giop::compile<iiop::generator_domain>
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
                          (busid, login_info.id, 0u, 0u, std::vector<unsigned char>(32u)
                           , std::vector<unsigned char>(256u), std::string()));

      OB_DIAG_REQUIRE(g, "Generated service context for starting session"
                      , "Failed generating context for starting session. This is a bug in the diagnostic tool")
    }
    std::vector<char> secret;
    boost::uint_t<32u>::least session_number = 0;
    std::string bus_login_id;
    {
      std::vector<fusion::vector2<std::string, std::string> >
        properties;
      properties.push_back(fusion::make_vector("offer.domain", "Demos"));

      ob_diag::service_context_list start_session_service_context;
      start_session_service_context.push_back
        (fusion::make_vector(0x42555300, empty_credential_data));
      ob_diag::make_request(socket, offer_registry_object_key, "findServices"
                            , giop::sequence[giop::string & giop::string]
                            , fusion::make_vector(properties), start_session_service_context);
      
      reply_buffer.resize(4096);
      size = socket.read_some
        (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
      reply_buffer.resize(size);

      OB_DIAG_REQUIRE(!ec, "Read reply with " << reply_buffer.size() << " bytes"
                      ,  "Failed reading with error " << ec.message())

      first = reply_buffer.begin(),  last = reply_buffer.end();

      fusion::vector0<> dummy;
      typedef reply_types<fusion::vector0<> > start_session_reply_type;
      start_session_reply_type start_session_reply(spirit::eps(false));

      g = qi::parse(first, last
                    , giop::compile<iiop::parser_domain>
                    (start_session_reply.message_grammar_)
                    , start_session_reply.attribute)
        && first == last;

      OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                      , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

      start_session_reply_type::variant_attribute_type start_session_variant_attr
        = fusion::at_c<3u>(fusion::at_c<0u>(start_session_reply.attribute));

      OB_DIAG_FAIL(!boost::get<start_session_reply_type::system_exception_attribute_type>
                   (&start_session_variant_attr)
                   , "A exception was not thrown!")
      
      start_session_reply_type::system_exception_attribute_type& system_exception
       = boost::get<start_session_reply_type::system_exception_attribute_type>
        (start_session_variant_attr);
      
      {
        start_session_reply_type::service_context_list& start_session_service_context
          = fusion::at_c<0u>(fusion::at_c<0u>(start_session_reply.attribute));
        
        OB_DIAG_FAIL(start_session_service_context.size() == 0
                     , "System exception thrown doesn't contain any ServiceContext. Can't create session.")
        
        OB_DIAG_FAIL(fusion::at_c<0u>(system_exception) != "IDL:omg.org/CORBA/NO_PERMISSION:1.0"
                     , "System exception thrown is " << fusion::at_c<0u>(system_exception)
                     << ". Expecting \"IDL:omg.org/CORBA/NO_PERMISSION:1.0\" exception")

        std::cout << "Received " << start_session_service_context.size() << " service contexts" << std::endl;

        OB_DIAG_FAIL(fusion::at_c<1u>(system_exception) != 0x42555300
                     , "Minor code of system exception thrown is " << fusion::at_c<1u>(system_exception)
                     << ". Expecting 0x42555300 in exception")

        OB_DIAG_FAIL(fusion::at_c<0u>(start_session_service_context[0]) != 0x42555300
                     , "Service Context id of system exception thrown is " << fusion::at_c<0u>(start_session_service_context[0])
                     << ". Expecting 0x42555300 in exception")
          
        fusion::vector3<std::string, unsigned int, std::vector<char> > credential_reset;
        std::vector<char>::iterator first = fusion::at_c<1u>(start_session_service_context[0]).begin()
          , last = fusion::at_c<1u>(start_session_service_context[0]).end();
        g = qi::parse(first, last
                      , giop::compile<iiop::parser_domain>
                      (giop::endianness
                       [
                        giop::string & giop::ulong_ & (spirit::repeat(256u)[giop::octet])
                       ])
                      , credential_reset)
          && first == last;

        OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                        , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

        session_number = fusion::at_c<1u>(credential_reset);
        bus_login_id = fusion::at_c<0u>(credential_reset);

        std::cout << "Bus Login id " << bus_login_id << std::endl;
          
        {
          std::vector<char>const& challange = fusion::at_c<2u>(credential_reset);
          EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(key, 0);
          EVP_PKEY_decrypt_init(ctx);
          ::size_t out_length = 0;
          EVP_PKEY_decrypt(ctx, 0, &out_length, (unsigned char*)&challange[0], challange.size());
          secret.resize(out_length);
          std::cout << "Secret is " << out_length << " bytes" << std::endl;
          EVP_PKEY_decrypt(ctx, (unsigned char*)&secret[0], &out_length
                           , (unsigned char*)&challange[0], challange.size());
        }
      }
      assert(secret.size() >= 16u);
      secret.resize(16u);

      ob_diag::signed_call_chain signed_call_chain;
      {
        std::vector<char> hash(32u);
        {
          std::vector<char> data_to_be_hashed;
          const char operation_lit[] = "signChainFor";
          data_to_be_hashed.reserve(22 + std::strlen(operation_lit));
          data_to_be_hashed.push_back(2); // major version
          data_to_be_hashed.push_back(0); // minor version
          data_to_be_hashed.insert(data_to_be_hashed.end(), secret.begin(), secret.end()); // secret
          data_to_be_hashed.push_back(0u); // ticket 
          data_to_be_hashed.push_back(0u); // ticket 
          data_to_be_hashed.push_back(0u); // ticket 
          data_to_be_hashed.push_back(0u); // ticket 
          data_to_be_hashed.insert(data_to_be_hashed.end(), &operation_lit[0]
                                   , &operation_lit[0] + sizeof(operation_lit)-1);
          SHA256((unsigned char*)&data_to_be_hashed[0], data_to_be_hashed.size()
                 , (unsigned char*)&hash[0]);
        }

        std::vector<char> credential_data;
        output_iterator_type iterator(credential_data);
        g = karma::generate(iterator, giop::compile<iiop::generator_domain>
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
                          (busid, login_info.id
                           , session_number
                           , 0u /* ticket */
                           , hash
                           , std::vector<char>(256u)
                           , std::string()));

        OB_DIAG_REQUIRE(g, "Generated service context for starting session"
                        , "Failed generating context for starting session. This is a bug in the diagnostic tool")

        ob_diag::service_context_list service_context;
        service_context.push_back
          (fusion::make_vector(0x42555300, credential_data));
        ob_diag::make_request(socket, access_control_object_key
                              , "signChainFor", giop::string
                              , fusion::make_vector(bus_login_id)
                              , service_context);
        ob_diag::read_reply(socket
                            , spirit::repeat(256u)[giop::octet]
                            & giop::sequence[giop::octet]
                            , signed_call_chain);
      }      

      std::vector<char> find_services_credential_data;

      std::vector<char> find_services_hash(32u);
      {
        std::vector<char> data_to_be_hashed;
        const char find_services_lit[] = "findServices";
        data_to_be_hashed.reserve(22 + std::strlen(find_services_lit));
        data_to_be_hashed.push_back(2); // major version
        data_to_be_hashed.push_back(0); // minor version
        data_to_be_hashed.insert(data_to_be_hashed.end(), secret.begin(), secret.end()); // secret
        data_to_be_hashed.push_back(1u); // ticket 
        data_to_be_hashed.push_back(0u); // ticket 
        data_to_be_hashed.push_back(0u); // ticket 
        data_to_be_hashed.push_back(0u); // ticket 
        data_to_be_hashed.insert(data_to_be_hashed.end(), &find_services_lit[0]
                                 , &find_services_lit[0] + sizeof(find_services_lit)-1);
        SHA256((unsigned char*)&data_to_be_hashed[0], data_to_be_hashed.size()
               , (unsigned char*)&find_services_hash[0]);
      }

      output_iterator_type iterator(find_services_credential_data);
      g = karma::generate(iterator, giop::compile<iiop::generator_domain>
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
                          (busid, login_info.id
                           , session_number
                           , 1u /* ticket */
                           , find_services_hash
                           , /*signed_call_chain.signature*/std::vector<char>(256u)
                           , /*signed_call_chain.encoded*/std::string()));

      OB_DIAG_REQUIRE(g, "Generated service context for starting session"
                      , "Failed generating context for starting session. This is a bug in the diagnostic tool")

      ob_diag::service_context_list bus_session_service_context;
      bus_session_service_context.push_back
        (fusion::make_vector(0x42555300, find_services_credential_data));
      ob_diag::make_request(socket, offer_registry_object_key, "findServices"
                            , giop::sequence[giop::string & giop::string]
                            , fusion::make_vector(properties)
                            , bus_session_service_context);

      {      
        typedef ::reference_types<std::vector<char>::iterator> reference_types;
        reference_types reference_types_;
        typedef reference_types::reference_attribute_type reference_arg_type;
      
        std::vector<fusion::vector3<reference_arg_type, std::vector<fusion::vector2<std::string, std::string> >
                                    , reference_arg_type> > offers;
        ob_diag::read_reply(socket
                            , giop::sequence
                              [
                               reference_types_.reference_grammar_
                               & giop::sequence[giop::string & giop::string]
                               & reference_types_.reference_grammar_
                              ]
                            , offers);

        std::cout << "Found " << offers.size() << " offers" << std::endl;
      }
    }
    
  }
  catch(ob_diag::require_error const&)
  {
  }
}
