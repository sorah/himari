require 'rack/oauth2'
require 'openid_connect'

require 'himari/token_string'

module Himari
  class AccessToken
    include TokenString

    class Bearer < Rack::OAuth2::AccessToken::Bearer
      def token_response(options = {})
        super.tap do |r|
          r[:token_type] = 'Bearer' # https://github.com/nov/openid_connect_sample/blob/a5b7ee5b63508d99a3a36b4537809dfa64ba3b1f/lib/token_endpoint.rb#L37
        end
      end
    end

    def self.magic_header
      'hmat'
    end

    def self.default_lifetime
      3600
    end

    # @param authz [Himari::AuthorizationCode]
    def self.from_authz(authz)
      make(
        client_id: authz.client_id,
        claims: authz.claims,
        lifetime: authz.lifetime.access_token,
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
