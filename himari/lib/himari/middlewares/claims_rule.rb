require 'himari/rule'
require 'himari/item_providers/static'

module Himari
  module Middlewares
    class ClaimsRule
      RACK_KEY = 'himari.claims_rule'

      def initialize(app, kwargs = {}, &block)
        @app = app
        @rule = Himari::Rule.new(block: block, **kwargs)
        @provider = Himari::ItemProviders::Static.new([@rule])
      end

      attr_reader :app, :client

      def call(env)
        env[RACK_KEY] ||= []
        env[RACK_KEY] += [@provider]
        @app.call(env)
      end
    end
  end
end
