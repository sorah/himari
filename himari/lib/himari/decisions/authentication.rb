# frozen_string_literal: true

require 'himari/decisions/base'
require 'himari/session_data'

module Himari
  module Decisions
    class Authentication < Base
      Context = Struct.new(:provider, :claims, :user_data, :request, :grant_type, :refresh_info, keyword_init: true) do
        def initial?; grant_type.nil? || grant_type == :initial; end
        def refresh?; grant_type == :refresh_token; end
      end

      allow_effects(:allow, :deny, :skip)

      def initialize(refresh_info: nil)
        super()
        @refresh_info = refresh_info
      end

      attr_accessor :refresh_info

      def to_evolve_args
        {refresh_info: @refresh_info}
      end

      def as_log
        to_h.merge(refresh_info_set: !@refresh_info.nil?)
      end
    end
  end
end
