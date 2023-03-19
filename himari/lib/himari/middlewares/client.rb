require 'himari/client_registration'
require 'himari/item_providers/static'

module Himari
  module Middlewares
    class Client
      RACK_KEY = 'himari.clients'

      def initialize(app, kwargs = {})
        @app = app
        @client = Himari::ClientRegistration.new(**kwargs)
        @provider = Himari::ItemProviders::Static.new([@client])
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
