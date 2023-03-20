require 'himari/config'

module Himari
  module Middlewares
    class Config
      RACK_KEY = 'himari.config'

      def initialize(app, kwargs = {})
        @app = app
        @config = Himari::Config.new(**kwargs)
      end

      attr_reader :app, :config

      def call(env)
        env[RACK_KEY] = config
        unless config.preserve_rack_logger
          env['rack.logger'] = config.logger
        end
        @app.call(env)
      end
    end
  end
end
