require 'himari/decisions/base'
require 'himari/session_data'

module Himari
  module Decisions
    class Claims < Base
      class UninitializedError < StandardError; end
      class AlreadyInitializedError < StandardError; end

      Context = Struct.new(:request, :auth, keyword_init: true) do
        def provider; auth[:provider]; end
      end

      allow_effects(:continue, :skip)

      def initialize(claims: nil, user_data: nil, lifetime: nil)
        super()
        @claims = claims
        @user_data = user_data
        @lifetime = lifetime
      end

      attr_accessor :lifetime

      def to_evolve_args
        {
          claims: @claims.dup,
          user_data: @user_data.dup,
          lifetime: @lifetime&.to_i,
        }
      end

      def as_log
        to_h.merge(claims: @claims)
      end

      def output
        Himari::SessionData.make(claims: claims, user_data: user_data, lifetime: lifetime)
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
