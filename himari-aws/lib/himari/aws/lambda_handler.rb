require 'himari'
require 'himari/aws/secretsmanager_signing_key_rotation_handler'

require 'digest/sha2'
require 'aws-sdk-dynamodb'
require 'apigatewayv2_rack'

$stdout.sync = true

module Himari
  module Aws
    module LambdaHandler
      def self.app
        @app ||= make_app()
      end

      def self.config_ru
        a = Time.now
        retval = config_ru_from_task_root || config_ru_from_dynamodb
        b = Time.now
        $stdout.puts(JSON.generate(config_ru: {ts: b, elapsed_time: b-a}))
        retval
      end

      def self.config_ru_from_task_root
        return nil unless ENV['LAMBDA_TASK_ROOT']
        File.read(File.join(ENV['LAMBDA_TASK_ROOT'], 'config.ru'))
      rescue Errno::ENOENT, Errno::EPERM
        nil
      end

      def self.config_ru_from_dynamodb
        dgst = ENV.fetch('HIMARI_RACK_DIGEST')
        table_name = ENV.fetch('HIMARI_RACK_DYNAMODB_TABLE')
        pk, sk = "rack", "rack:#{dgst}"

        ddb = ::Aws::DynamoDB::Client.new()
        item = ddb.query(
          table_name: table_name,
          select: 'ALL_ATTRIBUTES',
          limit: 1,
          key_condition_expression: 'pk = :pk AND sk = :sk',
          expression_attribute_values: {":pk" => pk, ":sk" => sk},
        ).items.first

        unless item
          raise "item not found (pk=#{pk.inspect}, sk=#{sk.inspect}) on dynamodb table #{table_name} for config.ru"
        end

        content = item.fetch('file')
        content_dgst = Digest::SHA256.digest(content)
        raise "config.ru item content digest mismatch" if content_dgst != Base64.decode64(dgst)

        content
      end

      def self.make_app
        require 'rack'
        require 'rack/builder'
        Rack::Builder.new_from_string(config_ru)
      end

      def self.rack_handler(event:, context:)
        Apigatewayv2Rack.handle_request(event: event, context: context, app: app)
      end

      def self.secrets_rotation_handler(event:, context:)
        Himari::Aws::SecretsmanagerSigningKeyRotationHandler.handler(event: event, context: context)
      end
    end
  end
end
