require 'himari/signing_key'
require 'himari/item_providers/static'

module Himari
  module Middlewares
    class SigningKey
      RACK_KEY = 'himari.signing_keys'

      def initialize(app, kwargs = {})
        @app = app
        @signing_key = Himari::SigningKey.new(**kwargs)
        @provider = Himari::ItemProviders::Static.new([@signing_key])
      end

      attr_reader :app, :signing_key

      def call(env)
        env[RACK_KEY] ||= []
        env[RACK_KEY] += [@provider]
        @app.call(env)
      end
    end
  end
end
