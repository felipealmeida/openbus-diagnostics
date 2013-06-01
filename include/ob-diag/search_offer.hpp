/* (c) Copyright 2012 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_SEARCH_OFFER_HPP
#define OB_DIAG_SEARCH_OFFER_HPP

#include <ob-diag/conditions.hpp>
#include <ob-diag/make_request.hpp>
#include <ob-diag/read_reply.hpp>
#include <ob-diag/create_session.hpp>
#include <ob-diag/signed_call_chain.hpp>
#include <ob-diag/reference_types.hpp>
#include <ob-diag/properties_options.hpp>
#include <ob-diag/create_connection.hpp>

#include <boost/asio.hpp>

namespace ob_diag {

struct offer_info
{
  std::vector<std::pair<std::string, std::string> > search_properties;
  
  typedef std::vector<char>::iterator reference_iterator_type;
  typedef ob_diag::reference_types<reference_iterator_type> reference_types;

  boost::shared_ptr<boost::asio::ip::tcp::socket> socket;
  boost::optional<reference_types::reference_attribute_type> offered_service_ref;
  std::vector<fusion::vector2<std::string, std::string> > offer_properties;
  boost::optional<reference_types::reference_attribute_type> offer_ref;

  offer_info(properties_options const& o)
    : search_properties(o.properties) {}
  offer_info() {}
};

void search_offer(boost::asio::ip::tcp::socket& bus_socket
                  , boost::asio::io_service& io_service
                  , std::vector<char>const& access_control_object_key
                  , std::vector<char>const& offer_registry_object_key
                  , std::string const& busid
                  , ob_diag::session& bus_session
                  , std::string const& login_info_id
                  , EVP_PKEY* key
                  , offer_info& oi)
{
  ob_diag::make_openbus_request(bus_socket, offer_registry_object_key, "findServices"
                                  , giop::sequence[giop::string & giop::string]
                                  , fusion::make_vector(oi.search_properties)
                                  , busid, login_info_id, bus_session);

  typedef reference_types<std::vector<char>::iterator> reference_types;
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
    oi.offered_service_ref = fusion::at_c<0>(offers[0]);
    oi.offer_properties = fusion::at_c<1>(offers[0]);
    oi.offer_ref = fusion::at_c<2>(offers[0]);

    {
      bool has_iiop_profile = false;
      
      std::vector<char> object_key;
      typedef std::vector
        <boost::variant<iiop::profile_body, reference_types::profile_body_1_1_attr
                        , ior::tagged_profile> > profiles_type;
      for(profiles_type::const_iterator profile_first = fusion::at_c<1u>(*oi.offered_service_ref).begin()
            , profile_last = fusion::at_c<1u>(*oi.offered_service_ref).end()
            ; profile_first != profile_last; ++profile_first)
      {
        if(iiop::profile_body const* p = boost::get<iiop::profile_body>(&*profile_first))
        {
          std::cout << "IIOP Profile Body" << std::endl;
          boost::shared_ptr<boost::asio::ip::tcp::socket> socket
            = create_connection(fusion::at_c<0u>(*p), fusion::at_c<1u>(*p), io_service);
          if(!has_iiop_profile)
          {
            oi.socket = socket;
            object_key = fusion::at_c<2u>(*p);
          }
          has_iiop_profile = true;
        }
        else if(reference_types::profile_body_1_1_attr const* p
                = boost::get<reference_types::profile_body_1_1_attr>(&*profile_first))
        {
          std::cout << "IIOP Profile Body 1." << (int)fusion::at_c<0u>(*p) << std::endl;
          boost::shared_ptr<boost::asio::ip::tcp::socket> socket
            = create_connection(fusion::at_c<1u>(*p), fusion::at_c<2u>(*p), io_service);
          if(!has_iiop_profile)
          {
            oi.socket = socket;
            object_key = fusion::at_c<3u>(*p);
          }
          has_iiop_profile = true;
        }
        else
        {
          std::cout << "Other Tagged Profiles" << std::endl;
        }
      }
      
      OB_DIAG_FAIL(!has_iiop_profile, "IOR has no IIOP Profile bodies. Can't communicate with TCP")

      std::cout << "Creating session to service" << std::endl;
        
      ob_diag::session session = ob_diag::create_session
        (*oi.socket, object_key, "_non_existent"
         , spirit::eps
         , fusion::vector0<>()
         , busid, login_info_id, key);

      std::cout << "SignChainFor" << std::endl;

      make_openbus_request(bus_socket, access_control_object_key, "signChainFor"
                           , giop::string, fusion::make_vector(/**/session.remote_id/**//*login_info_id*/)
                           , busid, login_info_id, bus_session);

      std::cout << "reading reply" << std::endl;

      fusion::vector2<std::vector<unsigned char>, std::vector<unsigned char> > signed_call_chain;
      read_reply(bus_socket, spirit::repeat(256u)[giop::octet] & giop::sequence[giop::octet], signed_call_chain);

      std::cout << "Making actual call" << std::endl;

      bool non_existent;
      make_openbus_request(*oi.socket, object_key, "_non_existent"
                           , spirit::eps, fusion::vector0<>()
                           , busid, login_info_id, session
                           , signed_call_chain);

      read_reply(*oi.socket, giop::bool_, non_existent);

      OB_DIAG_FAIL(non_existent, "ORB complained that object doesn't exist");
    }
            
    break;
  default:
    std::cout << "Found multiple offers" << std::endl;
    {
    }
    break;            
  }
}

}

#endif
