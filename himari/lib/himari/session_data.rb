require 'himari/token_string'

module Himari
  class SessionData
    include Himari::TokenString

    def initialize(claims: {}, user_data: {}, handle:, secret: nil, secret_hash: nil, expiry: nil)
      @claims = claims
      @user_data = user_data

      @handle = handle
      @secret = secret
      @secret_hash = secret_hash
      @expiry = expiry
    end

    def self.magic_header
      'hmas'
    end

    def self.default_lifetime
      3600
    end

    attr_reader :claims, :user_data

    def as_log
      {
        handle: handle,
        claims: claims,
        expiry: expiry,
      }
    end

    def as_json
      {
        handle: handle,
        secret_hash: secret_hash,
        expiry: expiry,

        claims: claims,
        user_data: user_data,
      }
    end
  end
end
