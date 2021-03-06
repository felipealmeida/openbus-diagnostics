/* (c) Copyright 2013 Felipe Magno de Almeida
*
* Distributed under the Boost Software License, Version 1.0. (See
* accompanying file LICENSE_1_0.txt or copy at
* http://www.boost.org/LICENSE_1_0.txt)
*/

#ifndef OB_DIAG_PROPERTIES_OPTIONS_HPP
#define OB_DIAG_PROPERTIES_OPTIONS_HPP

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>

namespace ob_diag {

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

  std::vector<std::string> tokens;
  boost::algorithm::split(tokens, v, boost::algorithm::is_space());

  for(std::vector<std::string>::const_iterator first = tokens.begin()
        , last = tokens.end(); first != last; ++first)
  {
    std::string::const_iterator equal_sign = std::find(first->begin(), first->end(), '=');
    if(equal_sign != first->end())
      r.properties.push_back(std::make_pair(std::string(first->begin(), equal_sign)
                                            , std::string(boost::next(equal_sign), first->end())));
    else
      r.properties.push_back(std::make_pair(std::string(first->begin(), equal_sign), std::string()));
  }
  any = r;
}

}

#endif
