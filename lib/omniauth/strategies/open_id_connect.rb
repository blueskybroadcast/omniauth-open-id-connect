require 'omniauth-oauth2'
require 'openid_connect'

module OmniAuth
  module Strategies
    class OpenIdConnect < OmniAuth::Strategies::OAuth2
      option :name, 'open_id_connect'
      option :client_options, {
        identifier: nil,
        secret: nil,
        redirect_uri: nil,
        domain: nil,
        authorization_endpoint: nil,
        token_endpoint: nil,
        user_info_endpoint: nil,
      }
      option :scope, [:openid]
      option :response_type, 'code'
      option :member_type_attribute, nil
      option :app_options, { app_event_id: nil }

      uid { info[:uid] }

      info { raw_user_info }

      def request_phase
        OpenIDConnect.debug!
        redirect authorization_uri
      end

      def callback_phase
        account = Account.find_by(slug: account_slug)
        @app_event = account.app_events.where(id: options.app_options.app_event_id).first_or_create(activity_type: 'sso')
        error = request.params['error_description'].presence | request.params['error_reason'].presence || request.params['error'].presence
        if error || request.params['code'].blank?
          msg = error ? error : 'Missing param "Code"'
          @app_event.logs.create(level: 'error', text: msg)
          @app_event.fail!
          return fail!(error)
        end

        self.env['omniauth.auth'] = auth_hash
        self.env['omniauth.origin'] = '/' + account_slug
        self.env['omniauth.redirect_url'] = request.params['redirect_uri'].presence
        self.env['omniauth.app_event_id'] = @app_event.id
        call_app!
      rescue StandardError
        @app_event&.fail!
      end

      def auth_hash
        hash = AuthHash.new(provider: name, uid: uid)
        hash.info = info
        hash.credentials = @access_token
        hash
      end

      private

      def token_response
        return @token_response if defined?(@token_response)

        openid_client.authorization_code = request.params['code']
        @token_response = openid_client.access_token!
        @access_token = {
          token: @token_response.access_token,
          refresh_token: @token_response.refresh_token,
          expires_in: @token_response.expires_in,
        }
        @token_response
      end

      def raw_user_info
        return @raw_user_info if defined?(@raw_user_info)

        @identity_url = URI.parse token_response.raw_attributes['id'].to_s
        user_info_response = token_response.userinfo!

        if options.member_type_attribute.present?
          member_type = user_info_response.raw_attributes[options.member_type_attribute].presence
          if @identity_url.host.present? && !member_type
            openid_client.userinfo_endpoint = @identity_url
            identity_response = token_response.userinfo!
            member_type = identity_response.raw_attributes[options.member_type_attribute].presence
          end
        end

        @app_event.logs.create(level: 'info', text: user_info_response.inspect)
        @raw_user_info = {
          uid: user_info_response.raw_attributes['user_id'].presence || user_info_response.sub,
          first_name: user_info_response.given_name,
          last_name: user_info_response.family_name,
          email: user_info_response.email,
          username: user_info_response.preferred_username || user_info_response.email,
          member_type: member_type
        }
      end

      def account_slug
        request.params['slug'].presence ||
          self.env['omniauth.origin']&.gsub(/\//, '') ||
          session['omniauth.origin']&.gsub(/\//, '')
      end

      def authorization_uri
        opts = {
          response_type: options.response_type,
          scope: options.scope,
          display: options.login_page_display
        }
        openid_client.authorization_uri(opts)
      end

      def redirect_uri
        options.client_options.redirect_uri.presence || callback_url
      end

      def openid_client
        @client ||= OpenIDConnect::Client.new(provider_configs_hash)
      end

      def provider_domain
        return @provider_domain if defined?(@provider_domain)

        endpoint = URI.parse(options.client_options.domain.to_s)
        return nil if !endpoint.scheme || !endpoint.host
        @provider_domain = "#{endpoint.scheme}://#{endpoint.host}"
      end

      def discovered_configs
        @discovered_configs ||= OpenIDConnect::Discovery::Provider::Config.discover!(provider_domain)
      end

      def provider_configs_hash
        {
          identifier: options.client_options.identifier,
          secret: options.client_options.secret,
          redirect_uri: redirect_uri,
          scope: options.scope,
          authorization_endpoint: authorization_endpoint,
          token_endpoint: token_endpoint,
          userinfo_endpoint: userinfo_endpoint
        }
      end

      def authorization_endpoint
        uri = URI.parse(options.client_options.authorization_endpoint.to_s)
        return discovered_configs.authorization_endpoint unless uri.path.size > 1

        uri.host ? uri.to_s : endpoint_with(uri.path)
      end

      def token_endpoint
        uri = URI.parse(options.client_options.token_endpoint.to_s)
        return discovered_configs.token_endpoint unless uri.path.size > 1

        uri.host ? uri.to_s : endpoint_with(uri.path)
      end

      def userinfo_endpoint
        uri = URI.parse(options.client_options.userinfo_endpoint.to_s)
        return discovered_configs.userinfo_endpoint unless uri.path.size > 1

        uri.host ? uri.to_s : endpoint_with(uri.path)
      end

      def endpoint_with(path)
        "#{provider_domain}/#{path.gsub(/^\//, '')}"
      end
    end
  end
end
