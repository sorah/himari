require 'himari/access_token'

module Himari
  module Services
    class OidcUserinfoEndpoint
      # @param storage [Himari::Storages::Base]
      def initialize(storage:)
        @storage = storage
      end

      def app
        self
      end

      def call(env)
        Handler.new(storage: @storage, env: env).response
      end

      class Handler
        class InvalidToken < StandardError; end

        def initialize(storage:, env:)
          @storage = storage
          @env = env
        end

        def response
          # https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
          return [404, {'Content-Type' => 'application/json'}, ['{"error": "not_found"}']] unless %w(GET POST).include?(@env['REQUEST_METHOD'])

          raise InvalidToken unless given_token
          given_parsed_token = Himari::AccessToken::Format.parse(given_token)

          token = @storage.find_token(given_parsed_token.handler)
          raise InvalidToken unless token
          token.verify_expiry!()
          token.verify_secret!(given_parsed_token.secret)

          [
            200,
            {'Content-Type' => 'application/json; charset=utf-8'},
            [JSON.pretty_generate(token.claims), "\n"],
          ]
        rescue InvalidToken, Himari::AccessToken::SecretIncorrect, Himari::AccessToken::InvalidFormat, Himari::AccessToken::TokenExpired
          [
            401,
            {'Content-Type' => 'application/json', 'WWW-Authenticate' => 'error="invalid_token", error_description="invalid access token"'},
            [JSON.pretty_generate(error: 'invalid_token'), "\n"],
          ]
        end

        def given_token
          # Only supports Authorization Request Header Field method https://www.rfc-editor.org/rfc/rfc6750.html#section-2.1
          @given_token ||= begin
            ah = @env['HTTP_AUTHORIZATION']
            method, token = ah&.split(/\s+/, 2) # https://www.rfc-editor.org/rfc/rfc9110#name-credentials
            if method&.downcase == 'bearer' && token && !token.empty?
              token
            else
              nil
            end
          end
        end
      end
    end
  end
end
