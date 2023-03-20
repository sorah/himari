require 'aws-sdk-secretsmanager'
require 'himari/signing_key'
require 'himari/middlewares/signing_key'

module Himari
  module Aws
    class SecretsmanagerSigningKeyProvider
      def initialize(app, kwargs = {})
        @app = app
        @inner = Provider.new(**kwargs)
      end

      def call(env)
        env[Himari::Middlewares::SigningKey::RACK_KEY] ||= []
        env[Himari::Middlewares::SigningKey::RACK_KEY] += [@inner]
        @app.call(env)
      end

      class Provider
        def initialize(client: ::Aws::SecretsManager::Client.new, secret_id:, group: nil, kid_prefix:)
          @client = client
          @secret_id = secret_id
          @group = group
          @kid_prefix = kid_prefix
        end

        def collect(id: nil, active: nil, group: nil, **_remainder)
          return [] if group && group != @group
          case
          when id
            return [] unless id.start_with?("#{@kid_prefix}_")
            version_id = id[(@kid_prefix.size+1)..-1] || ''
            [secret_value_to_signing_key(@client.get_secret_value(secret_id: @secret_id, version_id: version_id))].compact

          when active
            [secret_value_to_signing_key(@client.get_secret_value(secret_id: @secret_id, version_stage: 'AWSCURRENT'))].compact

          else
            values = @client.describe_secret(secret_id: @secret_id)
              .then { |secret|  [secret, secret.version_ids_to_stages.keys] }
              .then { |(secret, versions)| versions.map { |v| @client.get_secret_value(secret_id: secret.arn, version_id: v) } }
            values.map { |v| secret_value_to_signing_key(v) }.compact
          end
        rescue ::Aws::SecretsManager::Errors::ResourceNotFoundException
          []
        end

        private def secret_value_to_signing_key(value, inactive: false)
          json = begin
            JSON.parse(value.secret_string)
          rescue JSON::ParserError
            warn "JSON::ParserError while parsing #{value.arn} #{value.version_id}"
            return nil
          end
          
          return nil unless json['kind'] == 'himari.signing_key'

          pkey = case json.fetch('kty')
          when 'rsa'
            OpenSSL::PKey::RSA.new(json.fetch('rsa').fetch('pem'), '')
          when 'ec'
            OpenSSL::PKey::EC.new(json.fetch('ec').fetch('pem'), '')
          else
            raise "#{value.arn} #{value.version_id} has invalid kty"
          end

          Himari::SigningKey.new(
            id: "#{@kid_prefix}_#{value.version_id}",
            pkey: pkey,
            alg: json.fetch('alg', nil),
            group: @group,
            inactive: !value.version_stages.include?('AWSCURRENT'),
          )
        end
      end
    end
  end
end

