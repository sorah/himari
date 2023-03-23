require 'omniauth'
require 'omniauth-oauth2'
require 'oauth2'
require 'digest/sha2'

require 'omniauth-himari/version'

module OmniAuth
  module Strategies
    class Himari < OmniAuth::Strategies::OAuth2
      class IdTokenMissing < StandardError; end
      class ConfigurationError < StandardError; end
      class VerificationError < StandardError; end

      option :name, 'himari'

      option :client_options, {}
      option :pkce, true
      option :verify_at_hash, true

      option :verify_options, {}
      option :use_userinfo, false

      option :jwks_url, nil

      option :user_agent, nil

      args %i(site)

      def client
        options.client_options.site ||= options.site
        options.client_options.authorize_url ||= '/oidc/authorize'
        options.client_options.token_url ||= '/public/oidc/token'
        options.client_options.userinfo_url ||= '/public/oidc/userinfo'
        options.client_options.access_token_class ||= AccessToken # https://gitlab.com/oauth-xx/oauth2/-/issues/628

        options.client_options.connection_opts ||= {}
        options.client_options.connection_opts[:headers] ||= {}
        options.client_options.connection_opts[:headers] = {
          'User-Agent' => user_agent,
        }.merge(options.client_options.connection_opts[:headers])

        raise ConfigurationError, "client_id and client_secret is required" unless options.client_id && options.client_secret
        raise ConfigurationError, "site is required" unless options.client_options.site
        super
      end

      uid { raw_info['sub'] }

      credentials do
        retval = {
          'token' => access_token.token,
          'expires' => access_token.expires?,
          'expires_at' => access_token.expires_at,
          'id_token' => access_token.params && access_token.params['id_token'],
        }
        raise IdTokenMissing, 'id_token is missing' unless retval['id_token']
        retval
      end

      info do
        {
          name: raw_info['name'] || raw_info['sub'],
          nickname: raw_info['preferred_username'],
          email: raw_info['email'],
          first_name: raw_info['given_name'],
          last_name: raw_info['family_name'],
          image: raw_info['picture'],
        }
      end

      extra do
        {
          userinfo_used: options.use_userinfo,
          id_token: id_token.to_h,
          raw_info: raw_info,
        }
      end

      def verify_at_hash!(id_token)
        return unless options.verify_at_hash

        function = case id_token.header['alg'] # this is safe as we've verified
        when 'ES256', 'RS256'; Digest::SHA256
        when 'ES384'; Digest::SHA384
        when 'ES512'; Digest::SHA512
        else
          raise VerificationError, "unknown hash function to verify at_hash for #{id_token.header['alg']}"
        end

        dgst = function.digest(access_token.token)
        expected_at_hash = Base64.urlsafe_encode64(dgst[0, dgst.size/2], padding: false)

        given_at_hash = id_token.claims['at_hash']

        unless given_at_hash == expected_at_hash
          raise VerificationError, "at_hash mismatch #{given_at_hash.inspect}, #{expected_at_hash.inspect}"
        end
      end

      def raw_info
        @raw_info ||= (!skip_info? && options.use_userinfo) ? access_token.get('/public/oidc/userinfo').parsed : id_token.claims
      end

      def faraday
        @faraday ||= Faraday.new(options.site, headers: {'User-Agent' => user_agent}) do |b|
          b.response :json
          b.response :raise_error
        end
      end

      def callback_url
        options[:redirect_uri] || (full_host + callback_path) # https://github.com/omniauth/omniauth-oauth2/pull/142
      end

      def user_agent
        options.user_agent || "OmniauthHimari/#{Omniauth::Himari::VERSION}"
      end

      def authorize_params
        super.tap do |params|
          params[:scope] = 'openid'
        end
      end

      IdToken = Struct.new(:claims, :header)

      def id_token
        @id_token ||= begin
          jwt = access_token.params['id_token'] or raise(IdTokenMissing, 'id_token is missing')
          retval = IdToken.new(*JWT.decode(
            jwt,
            nil,
            true,
            {
              algorithms: jwks.map { |k| k[:alg] }.compact.uniq,
              jwks: jwks,
              verify_aud: true,
              aud: options.client_id,
              verify_iss: true,
              iss: options.site,
              verify_expiration: true,
            }.merge(options.verify_options)
          ))
          verify_at_hash!(retval)
          retval
        end
      end

      def jwks
        JWT::JWK::Set.new(jwks_json).tap do |set|
          set.filter! { |k| k[:use] == 'sig' }
        end
      end

      def jwks_json
        faraday.get(options.jwks_url || 'public/jwks').body
      rescue Faraday::Error => e
        raise JwksUnavailable, "failed to retrieve jwks; #{e.inspect}"
      end

      # https://github.com/omniauth/omniauth-oauth2/pull/142
      class AccessToken < ::OAuth2::AccessToken
        private def extra_tokens_warning(*)
          # do nothing
        end

        def inspect
          "#<#{self.class.name}:0x#{self.__id__.to_s(16)}>"
        end
      end
    end
  end
end


