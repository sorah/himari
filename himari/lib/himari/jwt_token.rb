# frozen_string_literal: true

require 'json/jwt'

module Himari
  # Shared minting process for the JWTs Himari signs for relying parties: the OIDC ID Token
  # and the RFC 9068 access token. Holds the common claim derivation (registered claims merged
  # over the IdP claims) and the signing step (kid, optional JOSE header fields, signature).
  # Subclasses add their token-specific claims/header by overriding #final_claims / #jwt_header.
  class JwtToken
    def initialize(claims:, client_id:, signing_key:, issuer:, time: Time.now, lifetime: 3600)
      @claims = claims
      @client_id = client_id
      @signing_key = signing_key
      @issuer = issuer
      @time = time
      @lifetime = lifetime
    end

    attr_reader :claims, :client_id, :signing_key, :issuer

    # Registered claims common to every Himari-minted JWT. The IdP claims (sub and the rest) are
    # carried verbatim so the access token exposes the same claim set as the ID Token.
    def standard_claims
      claims.merge(
        iss: @issuer,
        aud: @client_id,
        iat: @time.to_i,
        nbf: @time.to_i,
        exp: (@time + @lifetime).to_i,
      )
    end

    def final_claims
      standard_claims
    end

    # JOSE header fields beyond kid; subclasses override (e.g. typ=at+jwt for RFC 9068).
    def jwt_header
      {}
    end

    def to_jwt
      jwt = JSON::JWT.new(final_claims)
      jwt.kid = @signing_key.id
      jwt_header.each { |k, v| jwt.header[k] = v }
      jwt.sign(@signing_key.pkey, @signing_key.alg.to_sym).to_s
    end
  end
end
