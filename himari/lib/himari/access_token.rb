# frozen_string_literal: true

require 'rack/oauth2'
require 'openid_connect'
require 'json/jwt'

require 'himari/token_string'
require 'himari/access_token_jwt'

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

    # Parse a presented access token into its opaque Format (handle + secret) for verification
    # against storage. Two on-the-wire shapes are accepted:
    #
    # - the opaque token "hmat.<handle>.<secret>" (TokenString format), or
    # - an RFC 9068 JWT (Himari::AccessTokenJwt) carrying the opaque token in its +hmat+ claim.
    #
    # For a JWT, the signature is verified first (requires signing_key_provider to resolve the
    # kid), then the embedded opaque token is returned so the caller validates the secret against
    # storage exactly as for an opaque token. Any malformed/unverifiable JWT becomes
    # TokenString::InvalidFormat so callers handle one failure type.
    #
    # @param signing_key_provider [Himari::ProviderChain<Himari::SigningKey>, nil]
    def self.parse(str, signing_key_provider: nil)
      return TokenString::Format.parse(magic_header, str) if str.to_s.start_with?("#{magic_header}.")

      parse_jwt(str, signing_key_provider)
    end

    def self.parse_jwt(str, signing_key_provider)
      raise TokenString::InvalidFormat, 'signing keys are required to verify a JWT access token' unless signing_key_provider

      jwt = JSON::JWT.decode(str, :skip_verification)
      key = jwt.kid && signing_key_provider.find(id: jwt.kid)
      raise TokenString::InvalidFormat, 'unknown or missing signing key (kid)' unless key

      jwt.verify!(key.pkey)

      hmat = jwt[magic_header]
      raise TokenString::InvalidFormat, 'missing hmat claim' unless hmat.is_a?(String) && hmat.start_with?("#{magic_header}.")

      TokenString::Format.parse(magic_header, hmat)
    rescue JSON::JWT::Exception, JSON::ParserError => e
      raise TokenString::InvalidFormat, "invalid JWT access token: #{e.class}"
    end

    # @param authz [Himari::AuthorizationCode]
    def self.from_authz(authz)
      make(
        client_id: authz.client_id,
        claims: authz.claims,
        scopes: authz.scopes,
        session_handle: authz.session_handle,
        lifetime: authz.lifetime.access_token,
      )
    end

    def initialize(handle:, client_id:, claims:, expiry:, scopes: [], session_handle: nil, secret: nil, secret_hash: nil)
      @handle = handle
      @client_id = client_id
      @claims = claims
      @scopes = scopes
      @session_handle = session_handle
      @expiry = expiry

      @secret = secret
      @secret_hash = secret_hash
      @secret_hash_prev = nil
      @verification = nil
    end

    attr_reader :handle, :client_id, :claims, :scopes, :session_handle, :expiry

    def userinfo
      claims.merge(
        aud: client_id,
      )
    end

    # @param token_string [String] the on-the-wire access token to deliver. Defaults to the
    #   opaque format; the token endpoint passes the RFC 9068 JWT when one was minted.
    def to_bearer(token_string: format.to_s)
      Bearer.new(
        access_token: token_string,
        expires_in: (expiry - Time.now.to_i).to_i,
      )
    end

    # Render this token as an RFC 9068 JWT (Himari::AccessTokenJwt). The opaque secret travels in
    # the JWT's hmat claim, so the token validates against storage the same way either form does.
    # exp is tied to this token's own expiry rather than recomputed, keeping both forms in sync.
    # @param signing_key [Himari::SigningKey]
    # @param issuer [String]
    def to_jwt(signing_key:, issuer:, now: Time.now)
      AccessTokenJwt.new(
        access: self,
        claims: claims,
        client_id: client_id,
        signing_key: signing_key,
        issuer: issuer,
        time: now,
        lifetime: expiry - now.to_i,
      ).to_jwt
    end

    def as_log
      {
        handle: handle,
        client_id: client_id,
        claims: claims,
        scopes: scopes,
        session_handle: session_handle,
        expiry: expiry,
      }
    end

    def as_json
      {
        handle: handle,
        secret_hash: secret_hash,
        client_id: client_id,
        claims: claims,
        scopes: scopes,
        session_handle: session_handle,
        expiry: expiry.to_i,
      }
    end
  end
end
