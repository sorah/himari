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

      Context = Struct.new(:claims, :user_data, :request, :client, keyword_init: true)

      allow_effects(:allow, :deny, :continue, :skip)

      def initialize(claims: {}, allowed_claims: DEFAULT_ALLOWED_CLAIMS, lifetime: 3600)
        super()
        @claims = claims
        @allowed_claims = allowed_claims
        self.lifetime = lifetime
      end

      attr_reader :claims, :allowed_claims
      attr_reader :lifetime

      def lifetime=(x)
        case x
        when LifetimeValue
          @lifetime = x
        else
          @lifetime = LifetimeValue.from_integer(x)
        end
      end

      def to_evolve_args
        {
          claims: @claims.dup,
          allowed_claims: @allowed_claims.dup,
          lifetime: @lifetime,
        }
      end

      def as_log
        to_h.merge(claims: output_claims, lifetime: @lifetime.to_h)
      end

      def output_claims
        claims.select { |k,_v| allowed_claims.include?(k) }
      end
    end
  end
end
