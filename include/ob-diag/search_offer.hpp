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
#include <ob-diag/make_call.hpp>

#include <boost/asio.hpp>

namespace ob_diag {

struct offer_info
{
  std::vector<std::pair<std::string, std::string> > search_properties;
  
  typedef std::vector<char>::iterator reference_iterator_type;
  typedef ob_diag::reference_types<reference_iterator_type> reference_types;

  struct offer
  {
    boost::shared_ptr<boost::asio::ip::tcp::socket> socket;
    boost::optional<reference_types::reference_attribute_type> offered_service_ref;
    std::vector<fusion::vector2<std::string, std::string> > offer_properties;
    boost::optional<reference_types::reference_attribute_type> offer_ref;
  };

  std::vector<offer> offers;

  offer_info(properties_options const& o)
    : search_properties(o.properties) {}
  offer_info() {}
};

void search_offer(reference_connection const& access_control_connection
                  , reference_connection const& offer_registry_connection
                  , boost::asio::io_service& io_service
                  , std::string const& busid
                  , ob_diag::session& bus_session
                  , std::string const& login_info_id
                  , EVP_PKEY* key
                  , offer_info& oi)
{
  ob_diag::make_openbus_request(offer_registry_connection, "findServices"
                                  , giop::sequence[giop::string & giop::string]
                                  , fusion::make_vector(oi.search_properties)
                                  , busid, login_info_id, bus_session);

  typedef reference_types<std::vector<char>::iterator> reference_types;
  reference_types reference_types_;
  typedef reference_types::reference_attribute_type reference_arg_type;
        
  typedef std::vector<fusion::vector3
                      <reference_arg_type
                       , std::vector<fusion::vector2<std::string, std::string> >
                       , reference_arg_type> > offers_type;
  offers_type offers;
  ob_diag::read_reply(offer_registry_connection
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
    OB_DIAG_ERR(true, "No offers found for the following properties: ")
    break;
  case 1:
    if (true)
      std::cout << "Found one offer, as expected" << std::endl;
    else
  default:
      std::cout << "Found multiple offers" << std::endl;


    for(offers_type::const_iterator offer_first = offers.begin()
          , offer_last = offers.end();offer_first != offer_last;++offer_first)
    {
      offer_info::offer offer;
      offer.offered_service_ref = fusion::at_c<0>(offers[0]);
      offer.offer_properties = fusion::at_c<1>(offers[0]);
      offer.offer_ref = fusion::at_c<2>(offers[0]);

      reference_connection ref_connection;
      try
      {
        ref_connection = create_connection_ref(fusion::at_c<1>(*offer.offered_service_ref), io_service);
      }
      catch(require_error const&)
      {
        continue;
      }

      oi.offers.push_back(offer);
      
      std::cout << "Creating session to service" << std::endl;

      ob_diag::session session = ob_diag::create_session
        (ref_connection, "_non_existent"
         , spirit::eps
         , fusion::vector0<>()
         , busid, login_info_id, key);

      bool non_existent;
      make_openbus_call(ref_connection, "_non_existent"
                        , spirit::eps, fusion::vector0<>()
                        , giop::bool_, non_existent
                        , session
                        , access_control_connection
                        , busid, login_info_id
                        , bus_session);

      OB_DIAG_ERR(non_existent, "ORB complained that object doesn't exist");
    }
            
    break;
  }
}

}

#endif
