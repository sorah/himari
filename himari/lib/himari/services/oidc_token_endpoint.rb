require 'rack/oauth2'
require 'openid_connect'
require 'himari/access_token'
require 'himari/id_token'

module Himari
  module Services
    class OidcTokenEndpoint
      class SigningKeyMissing < StandardError; end

      # @param client_provider [Himari::ProviderChain<Himari::ClientRegistration>]
      # @param signing_key_provider [Himari::ProviderChain<Himari::SigningKey>]
      # @param storage [Himari::Storages::Base]
      # @param issuer [String]
      def initialize(client_provider:, signing_key_provider:, storage:, issuer:)
        @client_provider = client_provider
        @signing_key_provider = signing_key_provider
        @storage = storage
        @issuer = issuer
      end

      def app
        Rack::OAuth2::Server::Token.new do |req, res|
          client = @client_provider.find(id: req.client_id) { |c,h| c.match_hint?(**h) }
          next req.invalid_client! unless client
          next req.invalid_client! unless client.match_secret?(req.client_secret)

          case req.grant_type
          when :authorization_code
            authz = @storage.find_authorization(req.code)
            unless authz
              puts "no authz"
              next req.invalid_grant! 
            end
            unless authz.valid_redirect_uri?(req.redirect_uri)
              puts "not valid redirect uri"
              next req.invalid_grant! 
            end
            if authz.expiry <= Time.now.to_i
              puts "expired"
              next req.invalid_grant! 
            end
            # TODO: PKCE verify_code_verifier!

            token = AccessToken.from_authz(authz)
            @storage.put_token(token)
            res.access_token = token.to_bearer

            if authz.openid
              signing_key = client.preferred_key_group ? @signing_key_provider.find(group: client.preferred_key_group, active: true) { |k,h| k.match_hint?(**h) } : @signing_key_provider.find(active: true) { |k| k.active? }
              raise SigningKeyMissing unless signing_key
              res.id_token = IdToken.from_authz(authz, signing_key: signing_key, access_token: token.format.to_s, issuer: @issuer).to_jwt
            end

            @storage.delete_authorization(authz)
          else
            req.unsupported_response_type!
          end
        end
      end
    end
  end
end
