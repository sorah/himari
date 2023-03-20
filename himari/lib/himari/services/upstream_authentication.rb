require 'himari/log_line'
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
            claims: session_data&.claims,
            decision: {
              claims: claims_result&.as_log&.reject{ |k,_v| %i(allowed explicit_deny).include?(k) },
              authentication: authn_result&.as_log,
            },
          }
        end
      end

      # @param auth [Hash] Omniauth Auth Hash
      # @param claims_rules [Array<Himari::Rule>] Claims Rules
      # @param authn_rules [Array<Himari::Rule>] Authentication Rules
      # @param logger [Logger]
      def initialize(auth:, request: nil, claims_rules: [], authn_rules: [], logger: nil)
        @request = request
        @auth = auth
        @claims_rules = claims_rules
        @authn_rules = authn_rules
        @logger = logger
      end

      # @param request [Rack::Request]
      def self.from_request(request)
        new(
          auth: request.env.fetch('omniauth.auth'),
          request: request,
          claims_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::ClaimsRule::RACK_KEY] || []).collect,
          authn_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::AuthenticationRule::RACK_KEY] || []).collect,
          logger: request.env['rack.logger'],
        )
      end

      def provider
        @auth&.fetch(:provider)
      end

      def perform
        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: perform', objid: self.object_id.to_s(16), uid: @auth[:uid], provider: @auth[:provider]))
        claims_result = make_claims()
        session_data = claims_result.decision.output

        authn_result = check_authn(claims_result, session_data)


        result = Result.new(claims_result, authn_result, session_data)
        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: result', objid: self.object_id.to_s(16), uid: @auth[:uid], provider: @auth[:provider], result: result.as_log))
        result
      end

      def make_claims
        context = Himari::Decisions::Claims::Context.new(request: @request, auth: @auth).freeze
        result = Himari::RuleProcessor.new(context, Himari::Decisions::Claims.new).run(@claims_rules)

        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: claims', objid: self.object_id.to_s(16), uid: @auth[:uid], provider: @auth[:provider], claims_result: result.as_log))

        begin
          claims = result.decision&.output&.claims
          raise UnauthorizedError.new(Result.new(result, nil, nil)) unless claims
        rescue Himari::Decisions::Claims::UninitializedError
          raise UnauthorizedError.new(Result.new(result, nil, nil))
        end

        result
      end

      def check_authn(claims_result, session_data)
        context = Himari::Decisions::Authentication::Context.new(provider: provider, claims: session_data.claims, user_data: session_data.user_data, request: @request).freeze
        result = Himari::RuleProcessor.new(context, Himari::Decisions::Authentication.new).run(@authn_rules)

        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: authentication', objid: self.object_id.to_s(16), uid: @auth[:uid], provider: @auth[:provider],  authn_result: result.as_log))

        raise UnauthorizedError.new(Result.new(claims_result, result, nil)) unless result.allowed
        result
      end
    end
  end
end
