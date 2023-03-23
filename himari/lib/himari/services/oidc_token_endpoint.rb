require 'rack/oauth2'
require 'digest/sha2'
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
      # @param logger [Logger]
      def initialize(client_provider:, signing_key_provider:, storage:, issuer:, logger: nil)
        @client_provider = client_provider
        @signing_key_provider = signing_key_provider
        @storage = storage
        @issuer = issuer
        @logger = logger
      end

      def call(env)
        app(env).call(env)
      rescue Rack::OAuth2::Server::Abstract::Error => e
        @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: returning error', req: env['himari.request_as_log'], client: client.as_log, err: e.class.inspect, err_content: e.protocol_params))
        e.finish
      end

      def app(env)
        Rack::OAuth2::Server::Token.new do |req, res|
          code_dgst = req.code ? Digest::SHA256.hexdigest(req.code) : nil
          client = @client_provider.find(id: req.client_id)
          unless client
            @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_client, no client registration', req: env['himari.request_as_log'], client_id: req.client_id, code_dgst: code_dgst))
            next req.invalid_client!
          end
          unless client.match_secret?(req.client_secret)
            @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_client, client secret mismatch', req: env['himari.request_as_log'], client: client.as_log, code_dgst: code_dgst))
            next req.invalid_client! 
          end

          case req.grant_type
          when :authorization_code
            authz = @storage.find_authorization(req.code)
            unless authz
              @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, no grant code found', req: env['himari.request_as_log'], client: client.as_log))
              next req.invalid_grant! 
            end
            unless authz.valid_redirect_uri?(req.redirect_uri)
              @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, redirect_uri mismatch', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
              next req.invalid_grant! 
            end
            if authz.expiry <= Time.now.to_i
              @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, expired grant', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
              next req.invalid_grant! 
            end
            if authz.pkce? && !req.verify_code_verifier!(authz.code_challenge, authz.code_challenge_method)
              # :nocov:
              @logger&.warn(Himari::LogLine.new('OidcTokenEndpoint: invalid_grant, invalid pkce', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log))
              next req.invalid_grant!
              # :nocov:
            end

            token = AccessToken.from_authz(authz) # TODO: lifetime
            @storage.put_token(token)
            res.access_token = token.to_bearer

            if authz.openid
              signing_key = @signing_key_provider.find(group: client.preferred_key_group, active: true)
              raise SigningKeyMissing unless signing_key
              res.id_token = IdToken.from_authz(authz, signing_key: signing_key, access_token: token.format.to_s, issuer: @issuer).to_jwt
            end

            @storage.delete_authorization(authz)
            @logger&.info(Himari::LogLine.new('OidcTokenEndpoint: issued', req: env['himari.request_as_log'], client: client.as_log, grant: authz.as_log, token: token.as_log, signing_key_kid: signing_key&.id))
          else
            req.unsupported_response_type!
          end
        end
      end
    end
  end
end
