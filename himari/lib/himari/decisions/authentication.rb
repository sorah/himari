require 'himari/decisions/base'
require 'himari/session_data'

module Himari
  module Decisions
    class Authentication < Base
      Context = Struct.new(:provider, :claims, :user_data, :request, keyword_init: true)

      allow_effects(:allow, :deny, :skip)

      def to_evolve_args
        {}
      end
    end
  end
end
