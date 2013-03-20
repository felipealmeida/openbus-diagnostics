
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

#include <boost/spirit/home/karma.hpp>

namespace giop = morbid::giop;
namespace iiop = morbid::iiop;

struct arguments_traits
{
  
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

      namespace fusion = boost::fusion;
      namespace mpl = boost::mpl;
      namespace karma = boost::spirit::karma;

      typedef giop::forward_back_insert_iterator<std::vector<char> > output_iterator_type;
      typedef std::vector<fusion::vector2<unsigned int, std::vector<char> > > service_context_list;

      typedef fusion::vector7<service_context_list
                              , unsigned int, bool, std::vector<char>, std::string
                              , std::vector<char>
                              , std::string>
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

      std::vector<char> object_key;
      const char object_key_lit[] = "OpenBus_2_0";
      object_key.insert(object_key.end(), &object_key_lit[0]
                        , &object_key_lit[0] + sizeof(object_key_lit)-1);
      std::string method("getFacet");
      std::string facet_interface("IDL:tecgraf/openbus/core/v2_0/services/access_control/AccessControl:1.0");
      
      request_header_grammar request_header_grammar_(giop::string);
      message_header_grammar message_header_grammar_(request_header_grammar_);
      message_attribute_type attribute
        (fusion::make_vector
         (request_attribute_type
          (service_context_list(), 1u, true, object_key
           , method, std::vector<char>(), facet_interface)));
      
      std::vector<char> buffer;
      output_iterator_type iterator(buffer);
      if(karma::generate(iterator, giop::compile<iiop::generator_domain>
                         (message_header_grammar_(giop::native_endian))
                         , attribute))
      {
        std::cout << "Generated " << buffer.size() << std::endl;

        boost::asio::write(socket, boost::asio::buffer(buffer)
                           , boost::asio::transfer_all(), ec);
        if(!ec)
        {
          std::cout << "Sent " << buffer.size() << std::endl;

          

        }
        else
        {
          std::cout << "Failed sending " << buffer.size() << std::endl;
        }        
      }
      else
      {
        std::cout << "Failed generating first message" << std::endl;
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
