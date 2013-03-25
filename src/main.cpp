/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#include <ob-diag/conditions.hpp>

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

template <typename A>
struct request_types
{
  typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
  typedef std::vector<fusion::vector2<unsigned int, std::vector<char> > > service_context_list;

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

template <typename A>
struct reply_types
{
  typedef std::vector<char>::iterator iterator_type;
  typedef fusion::vector3<std::string, unsigned int, unsigned int>
    system_exception_attribute_type;
  typedef boost::variant<system_exception_attribute_type
                         , A> variant_attribute_type;

  typedef std::vector<fusion::vector2<unsigned int, std::vector<char> > >
    service_context_list;
  typedef fusion::vector4<service_context_list, unsigned int, unsigned int
                          , variant_attribute_type>
    reply_attribute_type;
  typedef fusion::vector1<reply_attribute_type>
    message_attribute_type;
  typedef giop::grammars::system_exception_reply_body
    <iiop::parser_domain, iterator_type, system_exception_attribute_type>
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
       &
        args_grammar
       ) |
       (
        spirit::eps(phoenix::at_c<2u>(spirit::_val) == 2u)
        & system_exception_grammar_
       )
      )
    , message_grammar_(reply_grammar_)
  {}  
};

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
                    
    std::vector<char> object_key;
    const char object_key_lit[] = "OpenBus_2_0";
    object_key.insert(object_key.end(), &object_key_lit[0]
                      , &object_key_lit[0] + sizeof(object_key_lit)-1);
    std::string method("getFacet");
    std::string facet_interface
      ("IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0");

    typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
    request_types<fusion::vector1<std::string> > rt
      (giop::string, object_key, method
       , fusion::vector1<std::string>(facet_interface));
      
    std::vector<char> buffer;
    output_iterator_type iterator(buffer);
    bool g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                             (rt.message_header_grammar_(giop::native_endian))
                             , rt.attribute);


    OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                    , "Failed generating request. This is a bug in the diagnostic tool")

    boost::asio::write(socket, boost::asio::buffer(buffer)
                       , boost::asio::transfer_all(), ec);

    OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                    , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())

    buffer.resize(0);

    std::vector<char> reply_buffer(4096);
    std::size_t size = socket.read_some
      (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
    reply_buffer.resize(size);

    OB_DIAG_REQUIRE(!ec, "Read reply with " << reply_buffer.size() << " bytes"
                    ,  "Failed reading with error " << ec.message())

    typedef std::vector<char>::iterator iterator_type;
    iterator_type first = reply_buffer.begin()
      ,  last = reply_buffer.end();

    typedef ::reference_types<iterator_type> reference_types;
    reference_types reference_types_;
    typedef reference_types::reference_attribute_type arguments_attribute_type;

    typedef reply_types<arguments_attribute_type> get_facet_reply_type;
    get_facet_reply_type get_facet_reply(reference_types_.reference_grammar_);

    g = qi::parse(first, last
                  , giop::compile<iiop::parser_domain>(get_facet_reply.message_grammar_)
                  , get_facet_reply.attribute)
      && first == last;

    OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                    , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

    reply_buffer.resize(4096);

    get_facet_reply_type::variant_attribute_type variant_attr
      = fusion::at_c<3u>(fusion::at_c<0u>(get_facet_reply.attribute));

    OB_DIAG_FAIL(/*get_facet_reply_type::system_exception_attribute_type* attr = */boost::get
                 <get_facet_reply_type::system_exception_attribute_type>(&variant_attr)
                 , "A exception was thrown!")

    arguments_attribute_type& attr = boost::get<arguments_attribute_type>(variant_attr);

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

    // Reading buskey attribute
    OB_DIAG_REQUIRE(!ec, "Connection to hostname and port of bus was successful"
                    , "Connection to hostname and port of bus failed with error: " << ec.message())

    std::string busid;
    {
      request_types<fusion::vector0<> > get_busid_rt(spirit::eps, access_control_object_key
                                                     , "_get_busid"
                                                     , fusion::vector0<>());

      buffer.resize(0);
      iterator = output_iterator_type(buffer);
      g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                          (get_busid_rt.message_header_grammar_(giop::native_endian))
                          , get_busid_rt.attribute);


      OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                      , "Failed generating request. This is a bug in the diagnostic tool")

      boost::asio::write(socket, boost::asio::buffer(buffer)
                         , boost::asio::transfer_all(), ec);

      OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                      , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())
    
      reply_buffer.resize(4096);
      size = socket.read_some
        (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
      reply_buffer.resize(size);

      OB_DIAG_REQUIRE(!ec, "Read reply with " << reply_buffer.size() << " bytes"
                      ,  "Failed reading with error " << ec.message())

      first = reply_buffer.begin(),  last = reply_buffer.end();

      typedef std::string get_busid_args_attribute_type;
      typedef reply_types<get_busid_args_attribute_type> get_busid_reply_type;
      get_busid_reply_type get_busid_reply(giop::string);

      g = qi::parse(first, last
                    , giop::compile<iiop::parser_domain>
                    (get_busid_reply.message_grammar_)
                    , get_busid_reply.attribute)
        && first == last;

      OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                      , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

      get_busid_reply_type::variant_attribute_type get_busid_variant_attr
        = fusion::at_c<3u>(fusion::at_c<0u>(get_busid_reply.attribute));

      OB_DIAG_FAIL(/*get_busid_reply_type::system_exception_attribute_type* attr = */boost::get
                   <get_busid_reply_type::system_exception_attribute_type>
                   (&get_busid_variant_attr)
                   , "A exception was thrown!")

      busid = boost::get<get_busid_args_attribute_type>(get_busid_variant_attr);
    
      std::cout << "Returned busid " << busid << std::endl;
    }
    

    request_types<fusion::vector0<> > get_buskey_rt(spirit::eps, access_control_object_key
                                         , "_get_buskey"
                                         , fusion::vector0<>());
    buffer.clear();
    iterator = output_iterator_type(buffer);
    g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                        (get_buskey_rt.message_header_grammar_(giop::native_endian))
                        , get_buskey_rt.attribute);


    OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                    , "Failed generating request. This is a bug in the diagnostic tool")

    boost::asio::write(socket, boost::asio::buffer(buffer)
                       , boost::asio::transfer_all(), ec);

    OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                    , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())
    
    reply_buffer.resize(4096);
    size = socket.read_some
      (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
    reply_buffer.resize(size);

    OB_DIAG_REQUIRE(!ec, "Read reply with " << reply_buffer.size() << " bytes"
                    ,  "Failed reading with error " << ec.message())

    first = reply_buffer.begin(),  last = reply_buffer.end();

    typedef std::vector<unsigned char> get_buskey_args_attribute_type;
    typedef reply_types<get_buskey_args_attribute_type> get_buskey_reply_type;
    get_buskey_reply_type get_buskey_reply(giop::sequence[giop::octet]);

    g = qi::parse(first, last
                  , giop::compile<iiop::parser_domain>
                    (get_buskey_reply.message_grammar_)
                  , get_buskey_reply.attribute)
      && first == last;

    OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                    , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

    get_buskey_reply_type::variant_attribute_type get_buskey_variant_attr
      = fusion::at_c<3u>(fusion::at_c<0u>(get_buskey_reply.attribute));

    OB_DIAG_FAIL(/*get_buskey_reply_type::system_exception_attribute_type* attr = */boost::get
                 <get_buskey_reply_type::system_exception_attribute_type>
                 (&get_buskey_variant_attr)
                 , "A exception was thrown!")

    get_buskey_args_attribute_type& get_buskey_attr = boost::get<get_buskey_args_attribute_type>
      (get_buskey_variant_attr);
    
    std::cout << "Returned encoded buskey public key with size " << get_buskey_attr.size() << std::endl;

    EVP_PKEY* bus_key;
    {
      unsigned char const* buf = &get_buskey_attr[0];
      bus_key = d2i_PUBKEY(0, &buf, get_buskey_attr.size());
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

    typedef fusion::vector3<std::string, std::vector<unsigned char>
                            , std::vector<unsigned char> >
                            login_arguments_type;
    request_types<login_arguments_type> login_rt
      (
       (
        giop::string
        & giop::sequence[giop::octet]
        & +giop::octet
       )
       , access_control_object_key, "loginByPassword"
       , login_arguments_type(username, public_key_buffer, encrypted_block));

    buffer.resize(0);
    iterator = output_iterator_type(buffer);
    g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                        (login_rt.message_header_grammar_(giop::native_endian))
                        , login_rt.attribute);
    
    OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                    , "Failed generating request. This is a bug in the diagnostic tool")

    boost::asio::write(socket, boost::asio::buffer(buffer)
                       , boost::asio::transfer_all(), ec);

    OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                    , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())
    
    reply_buffer.resize(4096);
    size = socket.read_some
      (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
    reply_buffer.resize(size);

    OB_DIAG_REQUIRE(!ec, "Read reply with " << reply_buffer.size() << " bytes"
                    ,  "Failed reading with error " << ec.message())

    first = reply_buffer.begin(),  last = reply_buffer.end();

    typedef fusion::vector3<std::string, std::string, unsigned int> login_args_attribute_type;
    typedef reply_types<login_args_attribute_type> login_reply_type;
    login_reply_type login_reply(giop::string & giop::string & giop::ulong_);

    g = qi::parse(first, last
                  , giop::compile<iiop::parser_domain>
                  (login_reply.message_grammar_)
                  , login_reply.attribute)
      && first == last;

    OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                    , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

    login_reply_type::variant_attribute_type login_variant_attr
      = fusion::at_c<3u>(fusion::at_c<0u>(login_reply.attribute));

    OB_DIAG_FAIL(/*login_reply_type::system_exception_attribute_type* attr = */boost::get
                 <login_reply_type::system_exception_attribute_type>
                 (&login_variant_attr)
                 , "A exception was thrown!")

    login_args_attribute_type& login_attr = boost::get<login_args_attribute_type>
      (login_variant_attr);

    std::string login_id = fusion::at_c<0u>(login_attr);
    std::cout << "Succesfully logged in. LoginInfo.id is " << login_id << std::endl;

    std::vector<char> offer_registry_object_key;
    {
      std::vector<char> object_key;
      object_key.insert(object_key.end(), &object_key_lit[0]
                        , &object_key_lit[0] + sizeof(object_key_lit)-1);
      std::string method("getFacet");
      std::string facet_interface
        ("IDL:tecgraf/openbus/core/v2_0/services/offer_registry/OfferRegistry:1.0");

      typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
      request_types<fusion::vector1<std::string> > rt
        (giop::string, object_key, method
         , fusion::vector1<std::string>(facet_interface));
      
      std::vector<char> buffer;
      output_iterator_type iterator(buffer);
      bool g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                               (rt.message_header_grammar_(giop::native_endian))
                               , rt.attribute);

      OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                      , "Failed generating request. This is a bug in the diagnostic tool")

      boost::asio::write(socket, boost::asio::buffer(buffer)
                         , boost::asio::transfer_all(), ec);

      OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                      , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())

      std::vector<char> reply_buffer(4096);
      std::size_t size = socket.read_some
        (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
      reply_buffer.resize(size);

      OB_DIAG_REQUIRE(!ec, "Read reply with " << reply_buffer.size() << " bytes"
                      ,  "Failed reading with error " << ec.message())

      typedef std::vector<char>::iterator iterator_type;
      iterator_type first = reply_buffer.begin()
        ,  last = reply_buffer.end();

      typedef ::reference_types<iterator_type> reference_types;
      reference_types reference_types_;
      typedef reference_types::reference_attribute_type arguments_attribute_type;

      typedef reply_types<arguments_attribute_type> get_facet_reply_type;
      get_facet_reply_type get_facet_reply(reference_types_.reference_grammar_);

      g = qi::parse(first, last
                    , giop::compile<iiop::parser_domain>(get_facet_reply.message_grammar_)
                    , get_facet_reply.attribute)
        && first == last;

      OB_DIAG_REQUIRE(g, "Parsing reply succesfully"
                      , "Parsing reply failed. This is a bug in the diagnostic or a bug in OpenBus")

      get_facet_reply_type::variant_attribute_type variant_attr
        = fusion::at_c<3u>(fusion::at_c<0u>(get_facet_reply.attribute));

      OB_DIAG_FAIL(/*get_facet_reply_type::system_exception_attribute_type* attr = */boost::get
                   <get_facet_reply_type::system_exception_attribute_type>(&variant_attr)
                   , "A exception was thrown!")

      arguments_attribute_type& attr = boost::get<arguments_attribute_type>(variant_attr);

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
                          (busid, login_id, 0u, 0u, std::vector<unsigned char>(32u)
                           , std::vector<unsigned char>(256u), std::string()));

      OB_DIAG_REQUIRE(g, "Generated service context for starting session"
                      , "Failed generating context for starting session. This is a bug in the diagnostic tool")
    }
    {
      std::vector<fusion::vector2<std::string, std::string> >
        properties;
      properties.push_back(fusion::make_vector("offer.domain", "Demos"));
      
      typedef fusion::vector1<std::vector<fusion::vector2<std::string, std::string> > >
        find_service_arguments_type;
      typedef request_types<find_service_arguments_type> find_services_rt_type;
      find_services_rt_type::service_context_list start_session_service_context;
      start_session_service_context.push_back
        (fusion::make_vector(0x42555300, empty_credential_data));
      find_services_rt_type find_services_rt
        (
         (
          giop::sequence[giop::string & giop::string]
         )
         , offer_registry_object_key, "findServices"
         , find_service_arguments_type(properties), start_session_service_context);

      buffer.resize(0);
      iterator = output_iterator_type(buffer);
      g = karma::generate(iterator, giop::compile<iiop::generator_domain>
                          (find_services_rt.message_header_grammar_(giop::native_endian))
                          , find_services_rt.attribute);
      
      OB_DIAG_REQUIRE(g, "Generated buffer with request with " << buffer.size() << " bytes"
                      , "Failed generating request. This is a bug in the diagnostic tool")

      boost::asio::write(socket, boost::asio::buffer(buffer)
                         , boost::asio::transfer_all(), ec);

      OB_DIAG_REQUIRE(!ec, "Sent buffer with request"
                      , "Failed sending buffer with request with " << buffer.size() << " bytes and error " << ec.message())
        
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
          
        
      }
    }
    
  }
  catch(ob_diag::require_error const&)
  {
  }
}
