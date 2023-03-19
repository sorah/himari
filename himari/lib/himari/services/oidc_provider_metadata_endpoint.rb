module Himari
  module Services
    class OidcProviderMetadataEndpoint
      # @param signing_key_provider [Himari::ProviderChain<Himari::SigningKey>]
      def initialize(signing_key_provider:, issuer:)
        @signing_key_provider = signing_key_provider
        @issuer = issuer
      end

      def app
        self
      end

      def call(env)
        Handler.new(signing_key_provider: @signing_key_provider, issuer: @issuer, env: env).response
      end

      class Handler
        class InvalidToken < StandardError; end

        def initialize(signing_key_provider:, issuer:, env:)
          @signing_key_provider = signing_key_provider
          @issuer = issuer
          @env = env
        end

        def metadata
          signing_keys = @signing_key_provider.collect()
          {
            issuer: @issuer,
            authorization_endpoint: "#{@issuer}/oidc/authorize",
            token_endpoint: "#{@issuer}/public/oidc/token",
            userinfo_endpoint: "#{@issuer}/public/oidc/userinfo",
            jwks_uri: "#{@issuer}/public/jwks",
            scopes_supported: %w(openid),
            response_types_supported: ['code'], # violation: dynamic OpenID Provider MUST support code, id_token, token+id_token
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: signing_keys.map(&:alg).uniq.sort,
            claims_supported: %w(sub iss iat nbf exp),
          }
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
