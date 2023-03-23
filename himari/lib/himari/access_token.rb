require 'securerandom'
require 'base64'
require 'digest/sha2'
require 'rack/utils'

require 'rack/oauth2'
require 'openid_connect'

module Himari
  class AccessToken
    class SecretMissing < StandardError; end
    class SecretIncorrect < StandardError; end
    class TokenExpired < StandardError; end
    class InvalidFormat < StandardError; end

    Format = Struct.new(:handle, :secret, keyword_init: true) do
      HEADER = 'hmat'

      def self.parse(str)
        parts = str.split('.')
        raise InvalidFormat unless parts.size == 3
        raise InvalidFormat unless parts[0] == HEADER
        new(handle: parts[1], secret: parts[2])
      end

      def to_s
        "#{HEADER}.#{handle}.#{secret}"
      end
    end

    class Bearer < Rack::OAuth2::AccessToken::Bearer
      def token_response(options = {})
        super.tap do |r|
          r[:token_type] = 'Bearer' # https://github.com/nov/openid_connect_sample/blob/a5b7ee5b63508d99a3a36b4537809dfa64ba3b1f/lib/token_endpoint.rb#L37
        end
      end
    end

    def self.make(**kwargs)
      new(
        handle: SecureRandom.urlsafe_base64(32),
        secret: SecureRandom.urlsafe_base64(48),
        expiry: Time.now.to_i + 3600,
        **kwargs
      )
    end

    # @param authz [Himari::AuthorizationCode]
    def self.from_authz(authz)
      make(
        client_id: authz.client_id,
        claims: authz.claims,
      )
    end

    def initialize(handle:, client_id:, claims:, expiry:, secret: nil, secret_hash: nil)
      @handle = handle
      @client_id = client_id
      @claims = claims
      @expiry = expiry

      @secret = secret
      @secret_hash = secret_hash
    end

    attr_reader :handle, :client_id, :claims, :expiry

    def secret
      raise SecretMissing unless @secret
      @secret
    end

    def secret_hash
      @secret_hash ||= Base64.urlsafe_encode64(Digest::SHA384.digest(secret), padding: false)
    end

    def verify_secret!(given_secret)
      dgst = Base64.urlsafe_decode64(secret_hash)
      given_dgst = Digest::SHA384.digest(given_secret)
      raise SecretIncorrect unless Rack::Utils.secure_compare(dgst, given_dgst)
      @secret = given_secret
      true
    end

    def verify_expiry!(now = Time.now)
      raise TokenExpired if @expiry <= now.to_i
    end

    def format
      Format.new(handle: handle, secret: secret)
    end

    def to_bearer
      Bearer.new(
        access_token: format.to_s,
        expires_in: (expiry - Time.now.to_i).to_i,
      )
    end

    def as_log
      {
        handle: handle,
        client_id: client_id,
        claims: claims,
        expiry: expiry,
      }
    end

    def as_json
      {
        handle: handle,
        secret_hash: secret_hash,
        client_id: client_id,
        claims: claims,
        expiry: expiry.to_i,
      }
    end
  end
end
