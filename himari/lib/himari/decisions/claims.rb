# frozen_string_literal: true

require 'himari/decisions/base'
require 'himari/session_data'

module Himari
  module Decisions
    class Claims < Base
      class UninitializedError < StandardError; end
      class AlreadyInitializedError < StandardError; end

      Context = Struct.new(:request, :auth, :provider, :grant_type, :refresh_info, keyword_init: true) do
        def initial?; grant_type.nil? || grant_type == :initial; end
        def refresh?; grant_type == :refresh_token; end
      end

      allow_effects(:continue, :skip, :deny)

      def initialize(claims: nil, user_data: nil, lifetime: nil, refresh_info: nil)
        super()
        @claims = claims
        @user_data = user_data
        @lifetime = lifetime
        @refresh_info = refresh_info
      end

      attr_accessor :lifetime, :refresh_info

      def to_evolve_args
        {
          claims: @claims.dup,
          user_data: @user_data.dup,
          lifetime: @lifetime&.to_i,
          refresh_info: @refresh_info,
        }
      end

      def as_log
        to_h.merge(claims: @claims, refresh_info_set: !@refresh_info.nil?)
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
        raise UninitializedError, "Claims uninitialized; use decision.initialize_claims! to declare claims first (or rule order might be unintentional)" unless @claims

        @claims
      end

      def user_data
        claims # to raise UninitializedError
        @user_data
      end
    end
  end
end
