require 'rack/oauth2'
require 'openid_connect'
require 'base64'
require 'json/jwt'

module Himari
  class IdToken
    # @param authz [Himari::AuthorizationCode]
    def self.from_authz(authz, **kwargs)
      new(
        claims: authz.claims,
        client_id: authz.client_id,
        nonce: authz.nonce,
        **kwargs
      )
    end

    def initialize(claims:, client_id:, nonce:, signing_key:, issuer:, access_token: nil, time: Time.now)
      @claims = claims
      @client_id = client_id
      @nonce = nonce
      @signing_key = signing_key
      @issuer = issuer
      @access_token = access_token
      @time = time
    end

    attr_reader :claims, :nonce, :signing_key

    def final_claims
      # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
      claims.merge(
        iss: @issuer,
        aud: @client_id,
        iat: @time.to_i,
        nbf: @time.to_i,
        exp: (@time + 3600).to_i, # TODO: lifetime
      ).merge(
        @nonce ? { nonce: @nonce } : {}
      ).merge(
        @access_token ? { at_hash: at_hash } : {}
      )
    end

    def at_hash
      return nil unless @access_token
      dgst = @signing_key.hash_function.digest(@access_token)
      Base64.urlsafe_encode64(dgst[0, dgst.size/2], padding: false)
    end

    def to_jwt
      jwt = JSON::JWT.new(final_claims)
      jwt.kid = @signing_key.id
      jwt.sign(@signing_key.pkey, @signing_key.alg.to_sym).to_s
    end
  end
end
