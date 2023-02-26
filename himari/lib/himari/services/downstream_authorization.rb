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

      Result = Struct.new(:client, :claims, :authz_result) do
        def as_log
          {
            client: client.as_log,
            claims: claims,
            decision: {
              authorization: authz_result.as_log,
            },
          }
        end
      end

      # @param session [Himari::SessionData]
      # @param client [Himari::ClientRegistration]
      # @param request [Rack::Request]
      # @param authz_rules [Array<Himari::Rule>] Authorization Rules
      def initialize(session:, client:, request: nil, authz_rules: [])
        @session = session
        @client = client
        @request = request
        @authz_rules = authz_rules
      end

      # @param session [Himari::SessionData]
      # @param client [Himari::ClientRegistration]
      # @param request [Rack::Request]
      def self.from_request(session:, client:, request:)
        new(
          session: session,
          client: client,
          request: request,
          authz_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::AuthorizationRule::RACK_KEY] || []).collect,
        )
      end

      def perform
        context = Himari::Decisions::Authorization::Context.new(claims: @session.claims, user_data: @session.user_data, request: @request, client: @client).freeze

        authorization = Himari::RuleProcessor.new(context, Himari::Decisions::Authorization.new(claims: @session.claims.dup)).run(@authz_rules)
        raise ForbiddenError.new(authorization) unless authorization.allowed

        claims = authorization.decision.output
        Result.new(@client, claims, authorization)
      end
    end
  end
end
