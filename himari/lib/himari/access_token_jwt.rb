# frozen_string_literal: true

require 'himari/jwt_token'
require 'himari/access_token'

module Himari
  # RFC 9068 (JWT Profile for OAuth 2.0 Access Tokens) representation of an access token. The
  # signed JWT carries the same IdP claims as the ID Token for relying parties to consume
  # directly, plus the registered claims RFC 9068 requires. Himari still authenticates the token
  # by the opaque secret embedded in the +hmat+ claim (see Himari::AccessToken.parse), so the
  # JWT signature is an additional, self-contained guarantee for relying parties.
  class AccessTokenJwt < JwtToken
    # sub is the one RFC 9068 §2.2 required claim sourced from variable IdP claims rather than set
    # by us; fail closed at mint time if a misconfigured allowed_claims stripped it.
    class MissingSubject < StandardError; end

    # @param access [Himari::AccessToken] the minted, persisted opaque access token this JWT wraps
    def initialize(access:, **kwargs)
      super(**kwargs)
      @access = access
    end

    # https://www.rfc-editor.org/rfc/rfc9068.html#section-2.1
    def jwt_header
      {typ: 'at+jwt'}
    end

    # https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2
    def final_claims
      raise MissingSubject, 'RFC 9068 access token requires a sub claim' unless claims[:sub]

      standard_claims.merge(
        client_id: @client_id,
        jti: @access.handle,
        # The opaque access token Himari validates against storage; relying parties ignore it.
        AccessToken.magic_header.to_sym => @access.format.to_s,
      ).merge(scope_claim)
    end

    # https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2.1 — space-delimited granted scopes.
    private def scope_claim
      scopes = @access.scopes
      scopes && !scopes.empty? ? {scope: scopes.join(' ')} : {}
    end
  end
end
