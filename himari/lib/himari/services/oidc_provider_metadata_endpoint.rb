# frozen_string_literal: true

module Himari
  module Services
    class OidcProviderMetadataEndpoint
      # @param signing_key_provider [Himari::ProviderChain<Himari::SigningKey>]
      # @param registration_endpoint [String, nil] advertised when Dynamic Client Registration is enabled
      # @param client_id_metadata_document_supported [Boolean] advertised when OAuth Client ID Metadata Document support is enabled
      def initialize(signing_key_provider:, issuer:, registration_endpoint: nil, client_id_metadata_document_supported: false)
        @signing_key_provider = signing_key_provider
        @issuer = issuer
        @registration_endpoint = registration_endpoint
        @client_id_metadata_document_supported = client_id_metadata_document_supported
      end

      def app
        self
      end

      def call(env)
        Handler.new(signing_key_provider: @signing_key_provider, issuer: @issuer, registration_endpoint: @registration_endpoint, client_id_metadata_document_supported: @client_id_metadata_document_supported, env: env).response
      end

      class Handler
        class InvalidToken < StandardError; end

        def initialize(signing_key_provider:, issuer:, env:, registration_endpoint: nil, client_id_metadata_document_supported: false)
          @signing_key_provider = signing_key_provider
          @issuer = issuer
          @registration_endpoint = registration_endpoint
          @client_id_metadata_document_supported = client_id_metadata_document_supported
          @env = env
        end

        def metadata
          signing_keys = @signing_key_provider.collect
          {
            issuer: @issuer,
            authorization_endpoint: "#{@issuer}/oidc/authorize",
            token_endpoint: "#{@issuer}/public/oidc/token",
            userinfo_endpoint: "#{@issuer}/public/oidc/userinfo",
            jwks_uri: "#{@issuer}/public/jwks",
            registration_endpoint: @registration_endpoint,
            client_id_metadata_document_supported: @client_id_metadata_document_supported ? true : nil,
            scopes_supported: %w(openid refresh_token),
            response_types_supported: ['code'], # violation: dynamic OpenID Provider MUST support code, id_token, token+id_token
            grant_types_supported: %w(authorization_code refresh_token),
            token_endpoint_auth_methods_supported: %w(client_secret_basic client_secret_post none),
            code_challenge_methods_supported: %w(S256 plain),
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: signing_keys.map(&:alg).uniq.sort,
            claims_supported: %w(sub iss iat nbf exp),
          }.compact
        end

        def response
          # https://openid.net/specs/openid-connect-discovery-1_0.html#ProviderMetadata
          return [404, {'Content-Type' => 'application/json'}, ['{"error": "not_found"}']] unless @env['REQUEST_METHOD'] == 'GET'

          [
            200,
            {'Content-Type' => 'application/json; charset=utf-8'},
            [JSON.pretty_generate(metadata), "\n"],
          ]
        end
      end
    end
  end
end
