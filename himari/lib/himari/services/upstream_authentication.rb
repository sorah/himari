require 'himari/decisions/authentication'
require 'himari/decisions/claims'
require 'himari/middlewares/authentication_rule'
require 'himari/middlewares/claims_rule'
require 'himari/rule_processor'
require 'himari/session_data'
require 'himari/provider_chain'

module Himari
  module Services
    class UpstreamAuthentication
      class UnauthorizedError < StandardError
        # @param result [Himari::RuleProcessor::Result]
        def initialize(result)
          @result = result
          super("Unauthorized")
        end

        attr_reader :result

        def as_log
          result.as_log
        end
      end

      Result = Struct.new(:claims_result, :authn_result, :session_data) do
        def as_log
          {
            claims: session_data.claims,
            decision: {
              claims: claims_result.as_log.reject{ |k,_v| %i(allowed explicit_deny).include?(k) },
              authentication: authn_result.as_log,
            },
          }
        end
      end

      # @param auth [Hash] Omniauth Auth Hash
      # @param claims_rules [Array<Himari::Rule>] Claims Rules
      # @param authn_rules [Array<Himari::Rule>] Authentication Rules
      def initialize(auth:, request: nil, claims_rules: [], authn_rules: [])
        @request = request
        @auth = auth
        @claims_rules = claims_rules
        @authn_rules = authn_rules
      end

      # @param request [Rack::Request]
      def self.from_request(request)
        new(
          auth: request.env['omniauth.hash'],
          request: request,
          claims_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::ClaimsRule::RACK_KEY] || []).collect,
          authn_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::AuthenticationRule::RACK_KEY] || []).collect,
        )
      end

      def provider
        @auth&.fetch(:provider)
      end

      def perform
        claims_result = make_claims()
        session_data = claims_result.decision.output

        authn_result = check_authn(session_data)

        Result.new(claims_result, authn_result, session_data)
      end

      def make_claims
        context = Himari::Decisions::Claims::Context.new(request: @request, auth: @auth).freeze
        result = Himari::RuleProcessor.new(context, Himari::Decisions::Claims.new).run(@claims_rules)

        begin
          claims = result.decision&.output&.claims
          raise UnauthorizedError.new(result) unless claims
        rescue Himari::Decisions::Claims::UninitializedError
          raise UnauthorizedError.new(result)
        end

        result
      end

      def check_authn(session_data)
        context = Himari::Decisions::Authentication::Context.new(provider: provider, claims: session_data.claims, user_data: session_data.user_data, request: @request).freeze
        result = Himari::RuleProcessor.new(context, Himari::Decisions::Authentication.new).run(@authn_rules)

        raise UnauthorizedError.new(result) unless result.allowed
        result
      end
    end
  end
end
