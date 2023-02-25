require 'himari/decisions/base'

module Himari
  module Decisions
    class Claims < Base
      class UninitializedError < StandardError; end
      class AlreadyInitializedError < StandardError; end

      allow_effects(:allow, :continue, :deny, :skip)

      def initialize(claims: nil, user_data: nil)
        super()
        @claims = claims
        @user_data = user_data
      end

      def to_evolve_args
        {
          claims: @claims.dup,
          user_data: @user_data.dup,
        }
      end

      def initialize_claims!(claims = {})
        if @claims
          raise AlreadyInitializedError, "Claims already initialized; use decision.claims to make modification, or rule might be behaving wrong"
        end
        @claims = claims.dup
        @user_data = {}
      end

      def claims
        unless @claims
          raise UninitializedError, "Claims uninitialized; use decision.initialize_claims! to declare claims first (or rule order might be unintentional)" unless @claims
        end
        @claims
      end

      def user_data
        claims # to raise UninitializedError
        @user_data
      end
    end
  end
end
