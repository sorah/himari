# frozen_string_literal: true

require 'securerandom'
require 'himari/token_string'

module Himari
  class RefreshToken
    include TokenString

    def self.magic_header
      'hmrt'
    end

    def self.default_lifetime
      raise ArgumentError, "RefreshToken requires an explicit lifetime:"
    end

    def initialize(handle:, client_id:, claims:, session_handle:, expiry:, openid: false, scopes: [], secret: nil, secret_hash: nil, secret_hash_prev: nil, version: 1, updated_at: nil)
      @handle = handle
      @client_id = client_id
      @claims = claims
      @session_handle = session_handle
      @openid = openid
      @scopes = scopes
      @expiry = expiry

      @secret = secret
      @secret_hash = secret_hash
      @secret_hash_prev = secret_hash_prev
      @version = version
      @updated_at = updated_at || Time.now.to_i
      @verification = nil
    end

    attr_reader :handle, :client_id, :claims, :session_handle, :openid, :scopes, :expiry, :version, :updated_at

    # Rotate the token in place (same handle): mint a new current secret while keeping the
    # just-presented secret valid as the previous one, so a client whose rotation response is
    # lost can retry with the secret it still holds. The secret to keep is the hash verify!
    # matched (TokenString#verification) — whichever slot the client used; rotate is therefore
    # only valid after a successful verify!. version is bumped so a concurrent refresh against
    # the version we read fails the conditional update. expiry is preserved: the initial
    # lifetime is an absolute cap on the rotation chain, not slid forward on each refresh.
    def rotate(claims:, openid:, now: Time.now)
      raise TokenString::SecretMissing, "rotate requires a verified secret; call verify! first" unless verification

      self.class.new(
        handle:,
        client_id:,
        session_handle:,
        claims:,
        openid:,
        scopes:,
        secret: SecureRandom.urlsafe_base64(48),
        secret_hash_prev: verification.secret_hash,
        version: version + 1,
        updated_at: now.to_i,
        expiry:,
      )
    end

    def as_log
      {
        handle: handle,
        client_id: client_id,
        claims: claims,
        session_handle: session_handle,
        openid: openid,
        scopes: scopes,
        expiry: expiry,
        version: version,
        updated_at: updated_at,
        prev_secret_set: !secret_hash_prev.nil?,
      }
    end

    def as_json
      {
        handle: handle,
        secret_hash: secret_hash,
        secret_hash_prev: secret_hash_prev,
        client_id: client_id,
        claims: claims,
        session_handle: session_handle,
        openid: openid,
        scopes: scopes,
        expiry: expiry.to_i,
        version: version,
        updated_at: updated_at.to_i,
      }
    end
  end
end
