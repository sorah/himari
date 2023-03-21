require 'digest/sha2'

module Himari
  authz_attrs = %i(
    code
    client_id
    claims
    openid
    redirect_uri
    nonce
    code_challenge
    code_challenge_method
    created_at
    lifetime
    expiry
  )
  AuthorizationCode = Struct.new(*authz_attrs, keyword_init: true) do
    def self.make(**kwargs)
      new(
        code: SecureRandom.urlsafe_base64(32),
        created_at: Time.now.to_i,
        **kwargs,
      )
    end

    alias _expiry_raw expiry
    private :_expiry_raw
    def expiry
      self._expiry_raw || (self.expiry = created_at + (lifetime || 900))
    end

    def valid_redirect_uri?(given_uri)
      redirect_uri == given_uri
    end

    def pkce?
      !!(code_challenge && code_challenge_method)
    end

    def pkce_known_method?
      # https://datatracker.ietf.org/doc/html/rfc7636#section-4.2
      %w(S256 plain).include?(code_challenge_method.to_s)
    end

    def pkce_valid_challenge?
      # https://datatracker.ietf.org/doc/html/rfc7636#section-4.1
      case code_challenge_method.to_s
      when 'plain'
        (43..128).cover?(code_challenge.size)
      when 'S256'
        (43..45).cover?(code_challenge.size)
      end
    end

    def pkce_valid_request?
      pkce? && pkce_known_method? && pkce_valid_challenge?
    end

    def code_dgst_for_log
      @code_dgst_for_log ||= code ? Digest::SHA256.hexdigest(code) : nil
    end

    def as_log
      {
        code_dgst: code_dgst_for_log,
        client_id: client_id,
        claims: claims,
        nonce: nonce,
        openid: openid,
        created_at: created_at.to_i,
        lifetime: lifetime.to_i,
        expiry: expiry.to_i,
        pkce: pkce?,
        pkce_method: code_challenge_method,
        pkce_valid_chal: pkce_valid_challenge?,
      }
    end

    def as_json
      {
        code: code,
        client_id: client_id,
        claims: claims,
        openid: openid,
        redirect_uri: redirect_uri,
        nonce: nonce,
        code_challenge: code_challenge,
        code_challenge_method: code_challenge_method,
        created_at: created_at.to_i,
        lifetime: lifetime.to_i,
        expiry: expiry.to_i,
      }
    end
  end
end
