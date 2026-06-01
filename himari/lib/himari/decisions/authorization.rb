# frozen_string_literal: true

require 'himari/decisions/base'
require 'himari/lifetime_value'

module Himari
  module Decisions
    class Authorization < Base
      DEFAULT_ALLOWED_CLAIMS = %i(
        sub
        name
        nickname
        preferred_username
        profile
        picture
        website
        email
        email_verified
      )

      Context = Struct.new(:claims, :user_data, :request, :client, :scopes, :grant_type, keyword_init: true) do
        def initial?; grant_type.nil? || grant_type == :initial; end
        def refresh?; grant_type == :refresh_token; end
      end

      allow_effects(:allow, :deny, :continue, :skip)

      def initialize(claims: {}, allowed_claims: DEFAULT_ALLOWED_CLAIMS, lifetime: 3600, mint_jwt_access_token: false)
        super()
        @claims = claims
        @allowed_claims = allowed_claims
        @mint_jwt_access_token = mint_jwt_access_token
        self.lifetime = lifetime
      end

      attr_reader :claims, :allowed_claims
      attr_reader :lifetime

      # When set by an authz rule, the issued access token is an RFC 9068 JWT instead of an
      # opaque token (the token is still tracked and validated against storage either way).
      attr_accessor :mint_jwt_access_token

      def lifetime=(x)
        @lifetime = case x
        when LifetimeValue
          x
        else
          LifetimeValue.from_integer(x)
        end
      end

      def to_evolve_args
        {
          claims: @claims.dup,
          allowed_claims: @allowed_claims.dup,
          lifetime: @lifetime,
          mint_jwt_access_token: @mint_jwt_access_token,
        }
      end

      def as_log
        to_h.merge(claims: output_claims, lifetime: @lifetime.to_h, mint_jwt_access_token: @mint_jwt_access_token)
      end

      def output_claims
        claims.select { |k, _v| allowed_claims.include?(k) }
      end
    end
  end
end
