module Himari
  module Services
    class JwksEndpoint
      # @param signing_key_provider [Himari::ProviderChain<Himari::SigningKey>]
      def initialize(signing_key_provider:)
        @signing_key_provider = signing_key_provider
      end

      def app
        self
      end

      def call(env)
        Handler.new(signing_key_provider: @signing_key_provider, env: env).response
      end

      class Handler
        class InvalidToken < StandardError; end

        def initialize(signing_key_provider:, env:)
          @signing_key_provider = signing_key_provider
          @env = env
        end

        def response
          # https://www.rfc-editor.org/rfc/rfc7517#section-5
          return [404, {'Content-Type' => 'application/json'}, ['{"error": "not_found"}']] unless @env['REQUEST_METHOD'] == 'GET'

          signing_keys = @signing_key_provider.collect()

          [
            200,
            {'Content-Type' => 'application/json; charset=utf-8'},
            [JSON.pretty_generate(keys: signing_keys.map(&:as_jwk)), "\n"],
          ]
        end
      end
    end
  end
end
