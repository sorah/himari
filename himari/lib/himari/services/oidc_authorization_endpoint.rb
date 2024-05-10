require 'rack/oauth2'
require 'digest/sha2'
require 'openid_connect'

module Himari
  module Services
    class OidcAuthorizationEndpoint
      class ReauthenticationRequired < StandardError; end

      SUPPORTED_RESPONSE_TYPES = ['code'] # TODO: share with oidc metadata

      # @param authz [Himari::AuthorizationCode] pending (unpersisted) authz data
      # @param client [Himari::ClientRegistration]
      # @param storage [Himari::Storages::Base]
      # @param logger [Logger]
      def initialize(authz:, client:, storage:, logger: nil)
        @authz = authz
        @client = client
        @storage = storage
        @logger = logger
      end

      def call(env)
        app(env).call(env)
      rescue Rack::OAuth2::Server::Abstract::Error => e
        @logger&.warn(Himari::LogLine.new('OidcAuthorizationEndpoint: returning error', req: env['himari.request_as_log'], err: e.class.inspect, err_content: e.protocol_params))
        # XXX: finish???? https://github.com/nov/rack-oauth2/blob/v2.2.0/lib/rack/oauth2/server/authorize/error.rb#L19
        # Call https://github.com/nov/rack-oauth2/blob/v2.2.0/lib/rack/oauth2/server/abstract/error.rb#L25
        Rack::OAuth2::Server::Abstract::Error.instance_method(:finish).bind(e).call
      end

      def app(env)
        Rack::OAuth2::Server::Authorize.new do |req, res|
          # sanity check
          unless @client.id == req.client_id
            @logger&.warn(Himari::LogLine.new('OidcAuthorizationEndpoint: @client.id != req.client_id', req: env['himari.request_as_log'], known_client: @client.id, given_client: req.client_id))
            next req.bad_request!
          end
          raise "[BUG] client.id != authz.cilent_id" unless @authz.client_id == @client.id
          res.redirect_uri = req.verify_redirect_uri!(@client.redirect_uris)

          req.unsupported_response_type! if res.protocol_params_location == :fragment
          req.bad_request!(:request_uri_not_supported, "Request Object is not implemented") if req.request_uri || req.request
          req.bad_request!(:invalid_request, 'prompt=none should not contain any other value') if req.prompt.include?('none') && req.prompt.any? { |x| x != 'none' }
          raise ReauthenticationRequired if req.prompt.include?('login') || req.prompt.include?('select_account')

          requested_response_types = [*req.response_type]
          unless SUPPORTED_RESPONSE_TYPES.include?(requested_response_types.map(&:to_s).join(' '))
            next req.unsupported_response_type!
          end

          if requested_response_types.include?(:code)
            @authz.redirect_uri = res.redirect_uri
            @authz.nonce = req.nonce

            @authz.openid = req.scope.include?('openid')
            if req.code_challenge && req.code_challenge_method
              @authz.code_challenge = req.code_challenge
              @authz.code_challenge_method = req.code_challenge_method || 'plain'
              next req.bad_request!(:invalid_request, 'Invalid PKCE parameters') unless @authz.pkce_valid_request?
            elsif @client.require_pkce
              next req.bad_request!(:invalid_request, 'PKCE is mandatory')
            end

            @storage.put_authorization(@authz)
            res.code = @authz.code

            @logger&.debug(Himari::LogLine.new('OidcAuthorizationEndpoint: grant code', req: env['himari.request_as_log'], client: @client.as_log, claims: @authz.claims, code: @authz.code))
          end

          # if requested_response_types.include?(:token)
          #   token = AccessToken.from_authz(@authz)
          #   @storage.put_token(token)
          #   res.access_token = token.format.to_s
          # end

          # if requested_response_types.include?(:id_token)
          #   @id_token.nonce = req.nonce
          #   res.id_token = @id_token.to_jwt
          # end

          @logger&.info(Himari::LogLine.new('OidcAuthorizationEndpoint: authorized', req: env['himari.request_as_log'], client: @client.as_log, claims: @authz.claims, redirect_uri: @authz.redirect_uri, code_dgst: Digest::SHA256.hexdigest(@authz.code)))
          res.approve!
        end
      end
    end
  end
end
