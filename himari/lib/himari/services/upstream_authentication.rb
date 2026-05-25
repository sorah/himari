# frozen_string_literal: true

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
            session: session_data&.as_log,
            decision: {
              claims: claims_result&.as_log&.reject { |k, _v| %i(allowed explicit_deny).include?(k) },
              authentication: authn_result&.as_log,
            },
          }
        end
      end

      # @param auth [Hash, nil] Omniauth Auth Hash (nil on revalidation)
      # @param session [Himari::SessionData, nil] Existing session to revalidate (nil on initial login)
      # @param grant_type [Symbol] :initial for omniauth callback, :refresh_token for revalidation
      # @param claims_rules [Array<Himari::Rule>] Claims Rules
      # @param authn_rules [Array<Himari::Rule>] Authentication Rules
      # @param logger [Logger]
      def initialize(auth: nil, session: nil, grant_type: :initial, request: nil, claims_rules: [], authn_rules: [], logger: nil)
        raise ArgumentError, "auth or session is required" if auth.nil? && session.nil?

        @request = request
        @auth = auth
        @session = session
        @grant_type = grant_type
        @claims_rules = claims_rules
        @authn_rules = authn_rules
        @logger = logger
      end

      # @param request [Rack::Request]
      def self.from_request(request)
        new(
          auth: request.env.fetch('omniauth.auth'),
          grant_type: :initial,
          request: request,
          claims_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::ClaimsRule::RACK_KEY] || []).collect,
          authn_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::AuthenticationRule::RACK_KEY] || []).collect,
          logger: request.env['rack.logger'],
        )
      end

      # Re-run claims/authn rules against an existing session, e.g. on refresh_token grant.
      #
      # @param session [Himari::SessionData] existing session loaded from storage
      # @param request [Rack::Request]
      def self.revalidate_from_request(session:, request:)
        new(
          session: session,
          grant_type: :refresh_token,
          request: request,
          claims_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::ClaimsRule::RACK_KEY] || []).collect,
          authn_rules: Himari::ProviderChain.new(request.env[Himari::Middlewares::AuthenticationRule::RACK_KEY] || []).collect,
          logger: request.env['rack.logger'],
        )
      end

      def provider
        (@auth && @auth[:provider]) || @session&.user_data&.dig(:provider)
      end

      def uid_for_log
        (@auth && @auth[:uid]) || @session&.claims&.dig(:sub)
      end

      def perform
        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: perform', objid: object_id.to_s(16), uid: uid_for_log, provider: provider, grant_type: @grant_type))
        claims_result = make_claims
        base = derive_base_session(claims_result)

        authn_result = check_authn(claims_result, base)
        final_refresh_info = authn_result.decision&.refresh_info || claims_result.decision&.refresh_info
        session_data = base.with(refresh_info: final_refresh_info)

        result = Result.new(claims_result, authn_result, session_data)
        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: result', objid: object_id.to_s(16), uid: uid_for_log, provider: provider, grant_type: @grant_type, result: result.as_log))
        result
      end

      def make_claims
        context = Himari::Decisions::Claims::Context.new(request: @request, auth: @auth, provider: provider, grant_type: @grant_type, refresh_info: @session&.refresh_info).freeze
        result = Himari::RuleProcessor.new(context, Himari::Decisions::Claims.new).run(@claims_rules)

        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: claims', objid: object_id.to_s(16), uid: uid_for_log, provider: provider, grant_type: @grant_type, claims_result: result.as_log))

        if result.explicit_deny
          @logger&.warn(Himari::LogLine.new('UpstreamAuthentication: claims explicit deny', objid: object_id.to_s(16), uid: uid_for_log, provider: provider, grant_type: @grant_type, claims_result: result.as_log))
          raise UnauthorizedError.new(Result.new(result, nil, nil))
        end

        begin
          claims = result.decision&.output&.claims
          raise UnauthorizedError.new(Result.new(result, nil, nil)) unless claims
        rescue Himari::Decisions::Claims::UninitializedError
          raise UnauthorizedError.new(Result.new(result, nil, nil))
        end

        result
      end

      def derive_base_session(claims_result)
        decision = claims_result.decision
        if @session
          # revalidation: keep existing handle/secret/expiry, refresh claims/user_data
          @session.with(claims: decision.claims, user_data: decision.user_data)
        else
          decision.output
        end
      end

      def check_authn(claims_result, session_data)
        context = Himari::Decisions::Authentication::Context.new(provider: provider, claims: session_data.claims, user_data: session_data.user_data, request: @request, grant_type: @grant_type, refresh_info: @session&.refresh_info).freeze
        # Don't preseed decision.refresh_info from session; otherwise a no-op authn rule would clobber whatever
        # the claims rule wrote (via Claims#refresh_info=). Authn rules that want to preserve session.refresh_info
        # must read context.refresh_info and assign it explicitly.
        result = Himari::RuleProcessor.new(context, Himari::Decisions::Authentication.new).run(@authn_rules)

        @logger&.debug(Himari::LogLine.new('UpstreamAuthentication: authentication', objid: object_id.to_s(16), uid: uid_for_log, provider: provider, grant_type: @grant_type, authn_result: result.as_log))

        raise UnauthorizedError.new(Result.new(claims_result, result, nil)) unless result.allowed

        result
      end
    end
  end
end
