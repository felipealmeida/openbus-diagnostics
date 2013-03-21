
#include <boost/program_options.hpp>

#include <boost/asio.hpp>
#include <boost/fusion/include/vector.hpp>

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

  typedef fusion::vector7<service_context_list
                          , unsigned int, bool, std::vector<char>, std::string
                          , std::vector<char>
                          , A>
    request_attribute_type;
  typedef fusion::vector1<fusion::vector1<request_attribute_type> >
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
  message_attribute_type attribute;

  template <typename G, typename A0>
  request_types(G g, std::vector<char> const& object_key, std::string const& method, A0 a0)
    : request_header_grammar_(g)
    , message_header_grammar_(request_header_grammar_)
    , attribute(fusion::make_vector
                (request_attribute_type
                 (service_context_list(), 1u, true, object_key
                  , method, std::vector<char>(), a0)))
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

int main(int argc, char** argv)
{
  boost::program_options::options_description desc("Allowed options");
  desc.add_options()
    ("help", "Shows this message")
    ("host,h", boost::program_options::value<std::string>(), "Hostname of Openbus")
    ("port,p", boost::program_options::value<unsigned short>(), "Port of Openbus")
    ;

  boost::program_options::variables_map vm;
  boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc)
                                , vm);
  boost::program_options::notify(vm);

  if(vm.count("help") || !vm.count("host"))
  {
    std::cout << desc << std::endl;
    return 1;
  }

  std::string hostname = vm["host"].as<std::string>();
  unsigned short port = vm["port"].as<unsigned short>();

  boost::asio::io_service io_service;
  boost::asio::ip::tcp::socket socket(io_service, boost::asio::ip::tcp::endpoint());

  boost::system::error_code ec;

  boost::asio::ip::tcp::resolver resolver(io_service);
  boost::asio::ip::tcp::resolver::query query
    (boost::asio::ip::tcp::endpoint::protocol_type::v4(), hostname, "");
  boost::asio::ip::tcp::endpoint remote_endpoint = *resolver.resolve(query, ec);
  if(!ec)
  {
    std::cout << "Resolving hostname was successful" << std::endl;

    remote_endpoint.port(port);
  
    socket.connect(remote_endpoint, ec);

    if(!ec)
    {
      std::cout << "Connection to hostname and port of bus was successful" << std::endl;


      std::vector<char> object_key;
      const char object_key_lit[] = "OpenBus_2_0";
      object_key.insert(object_key.end(), &object_key_lit[0]
                        , &object_key_lit[0] + sizeof(object_key_lit)-1);
      std::string method("getFacet");
      std::string facet_interface
        ("IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0");

      typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
      request_types<std::string> rt(giop::string, object_key, method, facet_interface);
      
      std::vector<char> buffer;
      output_iterator_type iterator(buffer);
      if(karma::generate(iterator, giop::compile<iiop::generator_domain>
                         (rt.message_header_grammar_(giop::native_endian))
                         , rt.attribute))
      {
        std::cout << "Generated " << buffer.size() << std::endl;

        boost::asio::write(socket, boost::asio::buffer(buffer)
                           , boost::asio::transfer_all(), ec);
        if(!ec)
        {
          std::cout << "Sent " << buffer.size() << std::endl;

          std::vector<char> reply_buffer(4096);
          std::size_t size = socket.read_some
            (boost::asio::mutable_buffers_1(&reply_buffer[0], reply_buffer.size()), ec);
          reply_buffer.resize(size);

          if(!ec)
          {
            std::cout << "Read " << reply_buffer.size() << std::endl;
            typedef std::vector<char>::iterator iterator_type;
            iterator_type first = reply_buffer.begin()
              ,  last = reply_buffer.end();

            typedef ::reference_types<iterator_type> reference_types;
            reference_types reference_types_;
            typedef reference_types::reference_attribute_type arguments_attribute_type;

            typedef fusion::vector3<std::string, unsigned int, unsigned int>
              system_exception_attribute_type;
            typedef boost::variant<system_exception_attribute_type
                                   , arguments_attribute_type> variant_attribute_type;

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

            reply_grammar reply_grammar_
              (
               (
                spirit::eps(phoenix::at_c<2u>(spirit::_val) == 0u)
                & reference_types_.reference_grammar_
               ) |
               (
                spirit::eps(phoenix::at_c<2u>(spirit::_val) == 2u)
                & system_exception_grammar_
               )
              );

            message_grammar message_grammar_(reply_grammar_);
            namespace qi = boost::spirit::qi;
            message_attribute_type attribute;
            if(qi::parse(first, last
                         , giop::compile<iiop::parser_domain>(message_grammar_)
                         , attribute))
            {
              std::cout << "Succesful parsing" << std::endl;

              variant_attribute_type variant_attr
                = fusion::at_c<3u>(fusion::at_c<0u>(attribute));
              if(system_exception_attribute_type* attr = boost::get
                 <system_exception_attribute_type>(&variant_attr))
              {
                std::cout << "A exception was thrown!" << std::endl;
              }
              else if(arguments_attribute_type* attr = boost::get
                      <arguments_attribute_type>(&variant_attr))
              {
                std::cout << "Reply was received" << std::endl;
                if(fusion::at_c<0u>(*attr) == "IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0")
                {
                  std::cout << "Found reference for AccessControl for OpenBus" << std::endl;

                  typedef std::vector
                    <boost::variant<iiop::profile_body, reference_types::profile_body_1_1_attr
                                    , ior::tagged_profile> > profiles_type;
                  for(profiles_type::const_iterator first = fusion::at_c<1u>(*attr).begin()
                        , last = fusion::at_c<1u>(*attr).end(); first != last; ++first)
                  {
                    if(iiop::profile_body const* p = boost::get<iiop::profile_body>(&*first))
                    {
                      std::cout << "IIOP Profile Body" << std::endl;
                    }
                    else if(reference_types::profile_body_1_1_attr const* p
                            = boost::get<reference_types::profile_body_1_1_attr>(&*first))
                    {
                      std::cout << "IIOP Profile Body 1 1" << std::endl;

                      std::cout << "Hostname: " << fusion::at_c<1u>(*p)
                                << " Port: " << fusion::at_c<2u>(*p) << std::endl;

                      boost::asio::ip::tcp::resolver::query query
                        (boost::asio::ip::tcp::endpoint::protocol_type::v4(), hostname, "");
                      boost::asio::ip::tcp::endpoint remote_endpoint = *resolver.resolve(query, ec);
                      if(!ec)
                      {
                        std::cout << "Succesful querying hostname from IIOP Profile" << std::endl;
                      }
                      else
                      {
                        std::cout << "Querying hostname from IIOP Profile failed" << std::endl;
                      }
                    }
                    else
                    {
                      std::cout << "Other Tagged Profiles" << std::endl;
                    }
                  }
                }
                else
                {
                  std::cout << "Reference is not for AccessControl" << std::endl;
                }
              }
            }
            else
            {
              std::cout << "Failed parsing arguments" << std::endl;
            }

          }
          else
          {
            std::cout << "Failed reading: " << ec << std::endl;
          }
        }
        else
        {
          std::cout << "Failed sending " << buffer.size() << ": " << ec << std::endl;
        }        
      }
      else
      {
        std::cout << "Failed generating first message: " << ec << std::endl;
      }
      
    }
    else
    {
      std::cout << "Connection to hostname and port of bus failed" << std::endl;
    }
  }
  else
  {
    std::cout << "Resolving hostname failed" << std::endl;
  }
  
}
