require 'rack/oauth2'
require 'openid_connect'

module Himari
  module Services
    class OidcAuthorizationEndpoint
      SUPPORTED_RESPONSE_TYPES = ['code'] # TODO: share with oidc metadata

      # @param authz [Himari::AuthorizationCode] pending (unpersisted) authz data
      # @param client [Himari::ClientRegistration]
      # @param storage [Himari::Storages::Base]
      def initialize(authz:, client:, storage:)
        @authz = authz
        @client = client
        @storage = storage
      end

      def app
        Rack::OAuth2::Server::Authorize.new do |req, res|
          # sanity check
          req.bad_request! unless @client.id == req.client_id
          raise "[BUG] client.id != authz.cilent_id" unless @authz.client_id == @client.id
          res.redirect_uri = req.verify_redirect_uri!(@client.redirect_uris)

          req.unsupported_response_type! if res.protocol_params_location == :fragment
          req.bad_request!(:request_uri_not_supported, "Request Object is not implemented") if req.request_uri || req.request

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
            end

            @storage.put_authorization(@authz)
            res.code = @authz.code
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

          res.approve!
        end
      end
    end
  end
end
