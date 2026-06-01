# frozen_string_literal: true

require 'himari/dynamic_client_registration'
require 'himari/item_providers/storage'
require 'himari/middlewares/client'
require 'himari/middlewares/config'

module Himari
  module Middlewares
    # Enables RFC 7591 Dynamic Client Registration. Its presence in the Rack env
    # (RACK_KEY) is what turns on the registration endpoint and its advertisement in the
    # OIDC discovery document. It also appends a storage-backed provider to the client
    # chain (Middlewares::Client::RACK_KEY) so registered clients resolve through the same
    # client_provider.find(id:) lookup the OIDC endpoints already use.
    #
    # Must be placed after Middlewares::Config (it reads storage from the config).
    class DynamicClients
      RACK_KEY = 'himari.dynamic_clients'

      Options = Data.define(:registration_lifetime, :ignore_localhost_redirect_uri_port, :skip_consent, :scopes, :grant_types_supported, :response_types_supported, :token_endpoint_auth_methods_supported)

      # @param registration_lifetime [Integer] seconds a registration stays valid (default 180 days)
      # @param ignore_localhost_redirect_uri_port [Boolean] relax the port of loopback redirect_uris
      #   for registered clients (default true; see RFC 8252 §7.3)
      # @param skip_consent [Boolean] let registered clients bypass the consent page (default false)
      # @param scopes [Array<String>] recognised scopes inherited by registered clients; scopes
      #   outside this list are dropped from authorization requests (default openid, offline_access)
      def initialize(app, kwargs = {})
        @app = app
        @options = Options.new(
          registration_lifetime: kwargs.fetch(:registration_lifetime) { Himari::DynamicClientRegistration::REGISTRATION_LIFETIME },
          ignore_localhost_redirect_uri_port: kwargs.fetch(:ignore_localhost_redirect_uri_port, true),
          skip_consent: kwargs.fetch(:skip_consent, false),
          scopes: kwargs.fetch(:scopes, Himari::ClientRegistration::IMPLICIT_SCOPES),
          grant_types_supported: Himari::DynamicClientRegistration::SUPPORTED_GRANT_TYPES,
          response_types_supported: Himari::DynamicClientRegistration::SUPPORTED_RESPONSE_TYPES,
          token_endpoint_auth_methods_supported: Himari::DynamicClientRegistration::SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS,
        )
      end

      attr_reader :app

      def call(env)
        config = env[Himari::Middlewares::Config::RACK_KEY]
        raise "Himari::Middlewares::DynamicClients must be placed after Himari::Middlewares::Config" unless config

        env[RACK_KEY] = @options
        env[Himari::Middlewares::Client::RACK_KEY] ||= []
        env[Himari::Middlewares::Client::RACK_KEY] += [Himari::ItemProviders::Storage.new(storage: config.storage, skip_consent: @options.skip_consent, scopes: @options.scopes)]

        @app.call(env)
      end
    end
  end
end
