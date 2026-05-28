# frozen_string_literal: true

require 'securerandom'
require 'base64'
require 'digest/sha2'
require 'rack/utils'

module Himari
  module TokenString
    class Error < StandardError; end
    class SecretMissing < Error; end
    class SecretIncorrect < Error; end
    class TokenExpired < Error; end
    class InvalidFormat < Error; end

    # Outcome of a successful verify_secret!: which stored secret slot the presented secret
    # matched (:current or :previous) and the hash it matched against. nil until verified.
    Verification = Data.define(:via, :secret_hash)

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
          **kwargs,
        )
      end

      def parse(str)
        Format.parse(magic_header, str)
      end
    end

    def self.included(k)
      k.extend(ClassMethods)
    end

    def self.hash_secret(secret)
      Base64.urlsafe_encode64(Digest::SHA384.digest(secret), padding: false)
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
      @secret_hash ||= TokenString.hash_secret(secret)
    end

    # Optional second valid secret hash. Tokens that rotate in place (RefreshToken) keep the
    # previously-issued secret valid for one more turn so a client whose rotation response was
    # lost can retry. nil for single-secret tokens (AccessToken, SessionData).
    def secret_hash_prev
      @secret_hash_prev
    end

    def verify!(secret:, now: Time.now)
      verify_expiry!(now)
      verify_secret!(secret)
    end

    def verify_secret!(given_secret)
      given_dgst = Digest::SHA384.digest(given_secret)
      @verification =
        if secret_hash_match(secret_hash, given_dgst)
          Verification.new(via: :current, secret_hash: secret_hash)
        elsif secret_hash_prev && secret_hash_match(secret_hash_prev, given_dgst)
          Verification.new(via: :previous, secret_hash: secret_hash_prev)
        end
      raise SecretIncorrect unless @verification

      @secret = given_secret
      true
    end

    # The Verification from the last successful verify_secret!, or nil. Used for logging
    # (#via) and to let a rotating token keep the just-presented secret valid (#secret_hash).
    attr_reader :verification

    private def secret_hash_match(stored_hash, given_dgst)
      stored_dgst = Base64.urlsafe_decode64(stored_hash)
      Rack::Utils.secure_compare(stored_dgst, given_dgst)
    rescue ArgumentError
      raise SecretIncorrect
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
