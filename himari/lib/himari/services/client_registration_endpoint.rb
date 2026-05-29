# frozen_string_literal: true

require 'json'
require 'rack/request'
require 'himari/log_line'
require 'himari/dynamic_client_registration'

module Himari
  module Services
    # RFC 7591 OAuth 2.0 Dynamic Client Registration endpoint. Accepts a JSON client metadata
    # document via POST, persists a Himari::DynamicClientRegistration, and returns the client
    # information response (including a one-time client_secret for confidential clients).
    class ClientRegistrationEndpoint
      # @param storage [Himari::Storages::Base]
      # @param registration_lifetime [Integer] seconds a registration stays valid
      # @param ignore_localhost_redirect_uri_port [Boolean] relax loopback redirect_uri ports for
      #   registered clients (default true; see RFC 8252 §7.3)
      # @param logger [Logger, nil]
      def initialize(storage:, registration_lifetime: Himari::DynamicClientRegistration::REGISTRATION_LIFETIME, ignore_localhost_redirect_uri_port: true, logger: nil)
        @storage = storage
        @registration_lifetime = registration_lifetime
        @ignore_localhost_redirect_uri_port = ignore_localhost_redirect_uri_port
        @logger = logger
      end

      def app
        self
      end

      def call(env)
        request = Rack::Request.new(env)
        return error_response(405, :invalid_request, 'method not allowed') unless request.post?

        metadata = parse_body(request)
        return error_response(400, :invalid_client_metadata, 'request body must be a JSON object') unless metadata

        client = Himari::DynamicClientRegistration.register(
          metadata: metadata,
          lifetime: @registration_lifetime,
          ignore_localhost_redirect_uri_port: @ignore_localhost_redirect_uri_port,
          registration_ip: request.ip,
          registration_remote_addr: env['REMOTE_ADDR'],
          registration_x_forwarded_for: env['HTTP_X_FORWARDED_FOR'],
        )
        @storage.put_dynamic_client(client)

        @logger&.info(Himari::LogLine.new('ClientRegistrationEndpoint: registered', req: env['himari.request_as_log'], client: client.as_log))

        json_response(201, client.registration_response)
      rescue Himari::DynamicClientRegistration::ValidationError => e
        @logger&.warn(Himari::LogLine.new('ClientRegistrationEndpoint: rejected', req: env['himari.request_as_log'], err: e.error_code, message: e.message))
        error_response(400, e.error_code, e.message)
      end

      private def parse_body(request)
        return unless request.media_type == 'application/json'

        body = request.body.read
        parsed = JSON.parse(body, symbolize_names: true)
        parsed.is_a?(Hash) ? parsed : nil
      rescue JSON::ParserError
        nil
      end

      private def json_response(status, body)
        [
          status,
          {'Content-Type' => 'application/json', 'Cache-Control' => 'no-store', 'Pragma' => 'no-cache'},
          [JSON.generate(body), "\n"],
        ]
      end

      private def error_response(status, error, description)
        json_response(status, {error: error, error_description: description})
      end
    end
  end
end
