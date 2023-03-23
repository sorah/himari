require 'securerandom'
require 'base64'
require 'digest/sha2'
require 'rack/utils'

module Himari
  module TokenString
    class SecretMissing < StandardError; end
    class SecretIncorrect < StandardError; end
    class TokenExpired < StandardError; end
    class InvalidFormat < StandardError; end

    module ClassMethods
      def magic_header
        raise NotImplementedError
      end

      def default_lifetime
        raise NotImplementedError
      end

      def make(lifetime: nil, **kwargs)
        new(
          handle: SecureRandom.urlsafe_base64(32),
          secret: SecureRandom.urlsafe_base64(48),
          expiry: Time.now.to_i + (lifetime || default_lifetime),
          **kwargs
        )
      end

      def parse(str)
        Format.parse(magic_header, str)
      end
    end

    def self.included(k)
      k.extend(ClassMethods)
    end

    def handle
      @handle
    end

    def expiry
      @expiry
    end

    def secret
      raise SecretMissing unless @secret
      @secret
    end

    def secret_hash
      @secret_hash ||= Base64.urlsafe_encode64(Digest::SHA384.digest(secret), padding: false)
    end

    def verify!(secret:, now: Time.now)
      verify_expiry!(now)
      verify_secret!(secret)
    end

    def verify_secret!(given_secret)
      dgst = Base64.urlsafe_decode64(secret_hash) # TODO: rescue errors
      given_dgst = Digest::SHA384.digest(given_secret)
      raise SecretIncorrect unless Rack::Utils.secure_compare(dgst, given_dgst)
      @secret = given_secret
      true
    end

    def verify_expiry!(now = Time.now)
      raise TokenExpired if @expiry <= now.to_i
    end

    Format = Struct.new(:header, :handle, :secret, keyword_init: true) do
      def self.parse(header, str)
        parts = str.split('.')
        raise InvalidFormat unless parts.size == 3
        raise InvalidFormat unless parts[0] == header
        new(header: header, handle: parts[1], secret: parts[2])
      end

      def to_s
        "#{header}.#{handle}.#{secret}"
      end
    end

    def magic_header
      self.class.magic_header
    end

    def format
      Format.new(header: magic_header, handle: handle, secret: secret)
    end
  end
end
