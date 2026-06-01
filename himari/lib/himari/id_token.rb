# frozen_string_literal: true

require 'rack/oauth2'
require 'openid_connect'
require 'base64'
require 'json/jwt'

require 'himari/jwt_token'

module Himari
  class IdToken < JwtToken
    # @param authz [Himari::AuthorizationCode]
    def self.from_authz(authz, **kwargs)
      new(
        claims: authz.claims,
        client_id: authz.client_id,
        nonce: authz.nonce,
        lifetime: authz.lifetime.is_a?(Integer) ? authz.lifetime : authz.lifetime.id_token, # compat
        **kwargs,
      )
    end

    def initialize(nonce:, access_token: nil, **kwargs)
      super(**kwargs)
      @nonce = nonce
      @access_token = access_token
    end

    attr_reader :nonce

    def final_claims
      # https://openid.net/specs/openid-connect-core-1_0.html#IDToken
      standard_claims.merge(
        @nonce ? {nonce: @nonce} : {},
      ).merge(
        @access_token ? {at_hash: at_hash} : {},
      )
    end

    def at_hash
      return unless @access_token

      dgst = signing_key.hash_function.digest(@access_token)
      Base64.urlsafe_encode64(dgst[0, dgst.size / 2], padding: false)
    end
  end
end
