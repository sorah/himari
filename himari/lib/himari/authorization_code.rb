module Himari
  AuthorizationCode = Struct.new(:code, :client_id, :claims, :openid, :redirect_uri, :nonce, :expiry, keyword_init: true) do
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

    def as_json
      {
        code: code,
        client_id: client_id,
        claims: claims,
        openid: openid,
        redirect_uri: redirect_uri,
        nonce: nonce,
        expiry: expiry.to_i,
      }
    end
  end
end
