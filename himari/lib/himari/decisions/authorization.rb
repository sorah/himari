require 'himari/decisions/base'

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

      def initialize(claims: {}, allowed_claims: DEFAULT_ALLOWED_CLAIMS, lifetime: 3600 * 12)
        super()
        @claims = claims
        @allowed_claims = allowed_claims
        @lifetime = lifetime
      end

      attr_reader :claims, :allowed_claims, :lifetime

      def to_evolve_args
        {
          claims: @claims.dup,
          allowed_claims: @allowed_claims.dup,
          lifetime: @lifetime&.to_i,
        }
      end

      def as_log
        to_h.merge(claims: output, lifetime: @lifetime&.to_i)
      end

      def output
        claims.select { |k,_v| allowed_claims.include?(k) }
      end
    end
  end
end
