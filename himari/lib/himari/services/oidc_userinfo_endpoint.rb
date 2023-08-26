require 'himari/access_token'
require 'himari/token_string'
require 'himari/log_line'

module Himari
  module Services
    class OidcUserinfoEndpoint
      # @param storage [Himari::Storages::Base]
      # @param logger [Logger]
      def initialize(storage:, logger: nil)
        @storage = storage
        @logger = logger
      end

      def app
        self
      end

      def call(env)
        Handler.new(storage: @storage, env: env, logger: @logger).response
      end

      class Handler
        class InvalidToken < StandardError; end

        def initialize(storage:, env:, logger:)
          @storage = storage
          @env = env
          @logger = logger
        end

        def response
          # https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
          return [404, {'Content-Type' => 'application/json'}, ['{"error": "not_found"}']] unless %w(GET POST).include?(@env['REQUEST_METHOD'])

          raise InvalidToken unless given_token
          given_parsed_token = Himari::AccessToken.parse(given_token)

          token = @storage.find_token(given_parsed_token.handle)
          raise InvalidToken unless token
          token.verify_expiry!()
          token.verify_secret!(given_parsed_token.secret)

          @logger&.info(Himari::LogLine.new('OidcUserinfoEndpoint: returning', req: @env['himari.request_as_log'], token: token.as_log))
          [
            200,
            {'Content-Type' => 'application/json; charset=utf-8'},
            [JSON.pretty_generate(token.userinfo), "\n"],
          ]
        rescue InvalidToken, Himari::TokenString::SecretIncorrect, Himari::TokenString::InvalidFormat, Himari::TokenString::TokenExpired => e
          @logger&.warn(Himari::LogLine.new('OidcUserinfoEndpoint: invalid_token', req: @env['himari.request_as_log'], err: e.class.inspect, token: token&.as_log))
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
