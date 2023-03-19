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
    expiry
  )
  AuthorizationCode = Struct.new(*authz_attrs, keyword_init: true) do
    def self.make(**kwargs)
      new(
        code: SecureRandom.urlsafe_base64(32),
        expiry: Time.now.to_i + 900,
        **kwargs,
      )
    end

    def valid_redirect_uri?(given_uri)
      redirect_uri == given_uri
    end

    def pkce?
      code_challenge && code_challenge_method
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
        expiry: expiry.to_i,
      }
    end
  end
end
