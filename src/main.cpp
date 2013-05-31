/* (c) Copyright 2012 Felipe Magno de Almeida
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
  boost::asio::ip::tcp::resolver::iterator remote_iterator
    = resolver.resolve(query, ec);

  OB_DIAG_REQUIRE(remote_iterator != boost::asio::ip::tcp::resolver::iterator()
                  , "Succesful querying hostname(" << hostname << ") from IIOP Profile"
                  , "Querying hostname(" << hostname << ") from IIOP Profile failed with error " << ec.message() << ". Check /etc/hosts in the server for any misconfigured hostnames")

  boost::asio::ip::tcp::endpoint remote_endpoint = *remote_iterator;
  remote_endpoint.port(port);

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

struct properties_options
{
  std::vector<std::pair<std::string, std::string> > properties;
};

void validate(boost::any& any
              , std::vector<std::string>& values
              , properties_options*
              , int)
{
  // Make sure no previous assignment to 'a' was made.
  boost::program_options::validators::check_first_occurrence(any);
  std::string v = boost::program_options::validators::get_single_string(values);

  properties_options r;

  std::string::iterator equal_sign = std::find(v.begin(), v.end(), '=');
  if(equal_sign != v.end())
    r.properties.push_back(std::make_pair(std::string(v.begin(), equal_sign)
                                          , std::string(boost::next(equal_sign), v.end())));
  else
    r.properties.push_back(std::make_pair(std::string(v.begin(), equal_sign), std::string()));

  any = r;
}

struct offer_info
{
  std::vector<std::pair<std::string, std::string> > search_properties;
  
  boost::shared_ptr<boost::asio::ip::tcp::socket> socket;

  typedef std::vector<char>::iterator reference_iterator_type;
  typedef ::reference_types<reference_iterator_type> reference_types;

  boost::optional<reference_types::reference_attribute_type> offered_service_ref;
  std::vector<fusion::vector2<std::string, std::string> > offer_properties;
  boost::optional<reference_types::reference_attribute_type> offer_ref;

  offer_info(properties_options const& o)
    : search_properties(o.properties) {}
  offer_info() {}
};

int main(int argc, char** argv)
{
  try
  {
    boost::program_options::options_description desc("Allowed options");
    {
      using boost::program_options::value;
      desc.add_options()
        ("help", "Shows this message")
        ("host,h", value<std::string>(), "Hostname of Openbus")
        ("port,p", value<unsigned short>(), "Port of Openbus")
        ("username", value<std::string>(), "Username for authentication")
        ("password", value<std::string>(), "Password for authentatication")
        ("track-offer", value<std::vector<properties_options> >(), "List of name=value pairs of properties for tracking offers")
        ;
    }

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
    boost::asio::ip::tcp::socket bus_socket(io_service, boost::asio::ip::tcp::endpoint());

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
    bus_socket.connect(remote_endpoint, ec);

    OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of bus was successful"
                    , "Connection to hostname and port of bus failed with error: " << ec.message())
                    
    std::vector<char> openbus_object_key;
    {
      const char openbus_object_key_lit[] = "OpenBus_2_0";
      openbus_object_key.insert(openbus_object_key.end(), &openbus_object_key_lit[0]
                                , &openbus_object_key_lit[0] + sizeof(openbus_object_key_lit)-1);
    }

    ob_diag::make_request(bus_socket, openbus_object_key, "getFacet"
                          , giop::string
                          , fusion::make_vector
                          (std::string("IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0")));

    typedef std::vector<char>::iterator iterator_type;
    typedef ::reference_types<iterator_type> reference_types;
    reference_types reference_types_;
    typedef reference_types::reference_attribute_type arguments_attribute_type;

    arguments_attribute_type attr;
    ob_diag::read_reply(bus_socket, reference_types_.reference_grammar_, attr);

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

    // Reading busid attribute
    ob_diag::make_request(bus_socket, access_control_object_key
                          , "_get_busid", spirit::eps, fusion::vector0<>());

    ob_diag::read_reply(bus_socket, giop::string, busid);

    // Reading buskey attribute
    ob_diag::make_request(bus_socket, access_control_object_key
                          , "_get_buskey", spirit::eps, fusion::vector0<>());

    typedef std::vector<unsigned char> buskey_args_type;
    buskey_args_type buskey_args;
    ob_diag::read_reply(bus_socket, giop::sequence[giop::octet], buskey_args);

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

    ob_diag::make_request(bus_socket, access_control_object_key
                          , "loginByPassword"
                          , giop::string
                          & giop::sequence[giop::octet]
                          & +giop::octet
                          , fusion::make_vector(username, public_key_buffer, encrypted_block));

    ::login_info login_info;
    ob_diag::read_reply(bus_socket, giop::string & giop::string & giop::ulong_, login_info);

    std::cout << "Succesfully logged in. LoginInfo.id is " << login_info.id << std::endl;

    std::vector<char> offer_registry_object_key;

    {
      ob_diag::make_request(bus_socket, openbus_object_key, "getFacet"
                            , giop::string
                            , fusion::make_vector
                            (std::string("IDL:tecgraf/openbus/core/v2_0/services/offer_registry/OfferRegistry:1.0")));

      typedef std::vector<char>::iterator iterator_type;
      typedef ::reference_types<iterator_type> reference_types;
      reference_types reference_types_;
      typedef reference_types::reference_attribute_type arguments_attribute_type;

      arguments_attribute_type attr;
      ob_diag::read_reply(bus_socket, reference_types_.reference_grammar_, attr);

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

    boost::optional<ob_diag::session> session;
    std::vector<offer_info> tracking_offers;
    if(vm.count("track-offer") > 0)
    {
      std::vector<properties_options> search_tracking_offers
        = vm["track-offer"].as<std::vector<properties_options> >();
      tracking_offers.resize(search_tracking_offers.size());
      std::copy(search_tracking_offers.begin(), search_tracking_offers.end(), tracking_offers.begin());

      std::cout << "Tracking " << tracking_offers.size() << " offers" << std::endl;

      for(std::vector<offer_info>::iterator
            first = tracking_offers.begin()
            , last = tracking_offers.end()
            ;first != last; ++first)
      {
        std::vector<fusion::vector2<std::string, std::string> > properties;
        for(std::vector<std::pair<std::string, std::string> >::const_iterator
              prop_first = first->search_properties.begin()
              , prop_last = first->search_properties.end()
              ;prop_first != prop_last; ++prop_first)
        {
          std::cout << "Adding properties " << prop_first->first << '=' << prop_first->second << std::endl;
          properties.push_back(fusion::make_vector(prop_first->first, prop_first->second));
        }

        if(!session)
          session = ob_diag::create_session
            (bus_socket, offer_registry_object_key, "findServices"
             , giop::sequence[giop::string & giop::string]
             , fusion::make_vector(properties)
             , busid, login_info.id, key);
    
        ob_diag::make_openbus_request(bus_socket, offer_registry_object_key, "findServices"
                                      , giop::sequence[giop::string & giop::string]
                                      , fusion::make_vector(properties)
                                      , busid, login_info.id, *session);
      
        {      
          typedef ::reference_types<std::vector<char>::iterator> reference_types;
          reference_types reference_types_;
          typedef reference_types::reference_attribute_type reference_arg_type;
        
          std::vector<fusion::vector3<reference_arg_type, std::vector<fusion::vector2<std::string, std::string> >
                                      , reference_arg_type> > offers;
          ob_diag::read_reply(bus_socket
                              , giop::sequence
                              [
                               reference_types_.reference_grammar_
                               & giop::sequence[giop::string & giop::string]
                               & reference_types_.reference_grammar_
                              ]
                              , offers);

          switch(offers.size())
          {
          case 0:
            std::cout << "No offers found for the following properties: " << std::endl;
            break;
          case 1:
            std::cout << "Found one offer, as expected" << std::endl;
            first->offered_service_ref = fusion::at_c<0>(offers[0]);
            first->offer_properties = fusion::at_c<1>(offers[0]);
            first->offer_ref = fusion::at_c<2>(offers[0]);
            break;
          default:
            std::cout << "Found multiple offers" << std::endl;
            {
            }
            break;            
          }
        }
      }
    }
    else
    {
    }

    std::cout << "will wait for any changes" << std::endl;
    

  }
  catch(ob_diag::require_error const&)
  {
  }
}
