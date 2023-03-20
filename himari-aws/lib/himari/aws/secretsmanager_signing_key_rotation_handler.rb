# https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_how.html
require 'openssl'
require 'json'
require 'aws-sdk-secretsmanager'

# this file should be independently loadable to ease lambda deployment

module Himari
  module Aws
    module SecretsmanagerSigningKeyRotationHandler
      RotationRequest = Struct.new(:step, :id, :token, :secret, keyword_init: true)

      def self.handler(event:, context:)
        @secretsmanager ||= ::Aws::SecretsManager::Client.new()

        secret = prerequisite_check!(event)

        req = RotationRequest.new(
          step: event.fetch('Step'),
          token: event.fetch('ClientRequestToken'),
          id: event.fetch('SecretId'),
          secret: secret,
        )
        puts JSON.generate(plan: {step: req.step, token: req.token, id: req.id})

        case req.step
        when 'createSecret'
          create_secret(req)
        when 'setSecret'
          set_secret(req)
        when 'testSecret'
          test_secret(req)
        when 'finishSecret'
          finish_secret(req)
        else
          raise "Unknown Step: #{req.step}"
        end
      end

      def self.prerequisite_check!(event)
        secret = @secretsmanager.describe_secret(secret_id: event.fetch('SecretId'))
        raise "secret #{secret.arn.inspect} have not enabled rotation" unless secret.rotation_enabled
        stages = secret.version_ids_to_stages[event.fetch('ClientRequestToken')]
        raise "Secret version #{event.fetch('ClientRequestToken').inspect} has no stage for secret #{secret.arn.inspect}" unless stages
        raise "Secret version #{event.fetch('ClientRequestToken').inspect} is on AWSCURRENT for secret #{secret.arn.inspect}" if stages.include?('AWSCURRENT') && !stages.include?('AWSPENDING')
        raise "Secret version #{event.fetch('ClientRequestToken').inspect} is not on AWSPENDING for secret #{secret.arn.inspect}" unless stages.include?('AWSPENDING')
        secret
      end

      def self.create_secret(req)
        current = begin
          @secretsmanager.get_secret_value(secret_id: req.id, version_stage: 'AWSCURRENT')
        rescue ::Aws::SecretsManager::Errors::ResourceNotFoundException
          nil
        end
        puts "createSecret: current version is: #{current.version_id} @ #{current.arn}" if current

        begin
          @secretsmanager.get_secret_value(secret_id: req.id, version_id: req.token, version_stage: 'AWSPENDING')
        rescue ::Aws::SecretsManager::Errors::ResourceNotFoundException
          puts "createSecret: generating for #{req.token} @ #{req.id}"

          @secretsmanager.put_secret_value(
            secret_id: req.id,
            client_request_token: req.token,
            secret_string: generate_secret(req, current),
          )
        else
          puts "createSecret: do nothing for #{req.token} @ #{req.id}"
        end
      end

      def self.generate_secret(req, _current)
        param = JSON.parse(req.secret.tags.find { |t| t.name == ENV.fetch('HIMARI_KEYGEN_PARAM_TAG_KEY', 'HimariKey') }&.value || ENV.fetch('HIMARI_KEYGEN_PARAM_DEFAULT', '{"kty": "rsa", "len": 2048}'), symbolize_names: true)
        puts "createSecret: generate_secret with #{param.inspect}"

        case param.fetch(:kty, 'rsa').downcase
        when 'rsa'
          rsa = OpenSSL::PKey::RSA.generate(param.fetch(:len, 2048).to_i)
          JSON.pretty_generate({kind: 'himari.signing_key', kty: 'rsa', rsa: {pem: rsa.to_pem}})
        when 'ec'
          curve = case param.fetch(:len, 256).to_i
          when 256; 'prime256v1'
          when 384; 'secp384r1'
          when 521; 'secp521r1'
          else
            raise ArgumentError, "unknown len: #{param.inspect}"
          end
          ec = OpenSSL::PKey::EC.generate(curve)
          JSON.pretty_generate({kind: 'himari.signing_key', kty: 'ec', ec: {pem: ec.to_pem}})
        else
          raise ArgumentError, "unknown kty: #{param.inspect}"
        end
      end

      def self.set_secret(req)
        _check = @secretsmanager.get_secret_value(secret_id: req.id, version_id: req.token, version_stage: 'AWSPENDING')
        puts "setSecret: do nothing for #{req.token} @ #{req.id}"
      end

      def self.test_secret(req)
        _check = @secretsmanager.get_secret_value(secret_id: req.id, version_id: req.token, version_stage: 'AWSPENDING')
        puts "testSecret: do nothing for #{req.token} @ #{req.id}"
      end

      def self.finish_secret(req)
        current_version = req.secret.version_ids_to_stages.find { |k,v| v.include?('AWSCURRENT') }.first
        if current_version == req.token
          puts "finishSecret: #{current_version} on #{req.id} is on AWSCURRENT, do nothing"
          return
        end

        puts "finishSecret: update_secret_version_stage AWSCURRENT to #{req.token} from #{current_version} for #{req.id}"
        @secretsmanager.update_secret_version_stage(
          secret_id: req.id,
          version_stage: 'AWSCURRENT',
          move_to_version_id: req.token,
          remove_from_version_id: current_version,
        )
      end
    end
  end
end
