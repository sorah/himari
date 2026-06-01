# frozen_string_literal: true

require 'himari/decisions/authorization'
require 'himari/middlewares/authorization_rule'
require 'himari/rule_processor'
require 'himari/session_data'
require 'himari/provider_chain'

module Himari
  module Services
    class DownstreamAuthorization
      class ForbiddenError < StandardError
        # @param result [Himari::RuleProcessor::Result]
        def initialize(result)
          @result = result
          super("Forbidden")
        end

        attr_reader :result

        def as_log
          result.as_log
        end
      end

      Result = Struct.new(:client, :claims, :scopes, :lifetime, :authz_result) do
        def as_log
          {
            client: client.as_log,
            claims: claims,
            scopes: scopes,
            decision: {
              authorization: authz_result.as_log,
            },
          }
        end
      end

      # @param session [Himari::SessionData]
      # @param client [Himari::ClientRegistration]
      # @param request [Rack::Request] exposed to rules as context.request (an escape hatch); the
      #   engine never reads it, so requested scopes are supplied explicitly, never derived from it.
      # @param requested_scopes [Array<String>] scopes asked for, before the client's allow-list
      #   filter. The caller supplies them from the appropriate source: the authorization endpoint
      #   passes the request's parsed scope, the refresh flow the scopes recorded on the grant.
      # @param authz_rules [Array<Himari::Rule>] Authorization Rules
      # @param logger [Logger]
      def initialize(session:, client:, requested_scopes:, grant_type: :initial, request: nil, authz_rules: [], logger: nil)
        @session = session
        @client = client
        @grant_type = grant_type
        @request = request
        @requested_scopes = requested_scopes
        @authz_rules = authz_rules
        @logger = logger
      end

      # @param session [Himari::SessionData]
      # @param client [Himari::ClientRegistration]
      # @param request [Rack::Request]
      # @param requested_scopes [Array<String>] see #initialize; always supplied by the caller
      def self.from_request(session:, client:, request:, requested_scopes:, grant_type: :initial)
        new(
          session: session,
          client: client,
          grant_type: grant_type,
          request: request,
          requested_scopes: requested_scopes,
          authz_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::AuthorizationRule::RACK_KEY] || []).collect,
          logger: request.env['rack.logger'],
        )
      end

      def perform
        scopes = @client.filter_scopes(@requested_scopes)
        context = Himari::Decisions::Authorization::Context.new(claims: @session.claims, user_data: @session.user_data, request: @request, client: @client, scopes: scopes, grant_type: @grant_type).freeze

        authorization = Himari::RuleProcessor.new(context, Himari::Decisions::Authorization.new(claims: @session.claims.dup)).run(@authz_rules)
        raise ForbiddenError.new(Result.new(@client, nil, scopes, nil, authorization)) unless authorization.allowed

        claims = authorization.decision.output_claims
        lifetime = authorization.decision.lifetime
        Result.new(@client, claims, scopes, lifetime, authorization)
      end
    end
  end
end
