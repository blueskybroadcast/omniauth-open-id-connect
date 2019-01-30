require 'omniauth-oauth2'
require 'builder'

module OmniAuth
  module Strategies
    class OpenIdConnect < OmniAuth::Strategies::OAuth2
      option :name, 'open_id_connect'
    end
  end
end
