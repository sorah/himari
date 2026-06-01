# frozen_string_literal: true

require 'digest/sha2'
require 'securerandom'
require 'addressable/uri'
require 'himari/client_registration'

module Himari
  # A client created at runtime via RFC 7591 Dynamic Client Registration, persisted in
  # storage. This is purely a storage/registration record: the registration endpoint
  # interacts with it directly, while the OIDC endpoints only ever see the plain
  # ClientRegistration produced by #to_client_registration at the provider layer.
  class DynamicClientRegistration
    # Default registration lifetime; overridable per deployment via Middlewares::DynamicClients.
    REGISTRATION_LIFETIME = 180 * 86400

    SUPPORTED_GRANT_TYPES = %w(authorization_code refresh_token).freeze
    SUPPORTED_RESPONSE_TYPES = %w(code).freeze
    SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS = %w(none client_secret_basic client_secret_post).freeze

    DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD = 'client_secret_basic'

    MAX_REDIRECT_URIS = 32
    MAX_URI_LENGTH = 2000
    MAX_CLIENT_NAME_LENGTH = 60
    DANGEROUS_REDIRECT_URI_SCHEMES = %w(javascript data vbscript file blob).freeze

    # Raised on invalid client metadata. error_code maps to an RFC 7591 §3.2.2 error code.
    class ValidationError < StandardError
      def initialize(error_code, message)
        @error_code = error_code
        super(message)
      end

      attr_reader :error_code
    end

    # Build and validate a registration from RFC 7591 client metadata.
    #
    # @param metadata [Hash] parsed client metadata (symbolized keys) from the request body
    # @return [DynamicClientRegistration]
    def self.register(metadata:, registration_ip: nil, registration_remote_addr: nil, registration_x_forwarded_for: nil, lifetime: REGISTRATION_LIFETIME, ignore_localhost_redirect_uri_port: true, now: Time.now)
      raise ValidationError.new(:invalid_client_metadata, 'request body must be a JSON object') unless metadata.is_a?(Hash)

      auth_method = metadata.fetch(:token_endpoint_auth_method, DEFAULT_TOKEN_ENDPOINT_AUTH_METHOD).to_s
      unless SUPPORTED_TOKEN_ENDPOINT_AUTH_METHODS.include?(auth_method)
        raise ValidationError.new(:invalid_client_metadata, "unsupported token_endpoint_auth_method: #{auth_method}")
      end

      grant_types = Array(metadata[:grant_types] || %w(authorization_code)).map(&:to_s)
      unless (grant_types - SUPPORTED_GRANT_TYPES).empty?
        raise ValidationError.new(:invalid_client_metadata, "unsupported grant_types: #{(grant_types - SUPPORTED_GRANT_TYPES).join(",")}")
      end

      response_types = Array(metadata[:response_types] || %w(code)).map(&:to_s)
      unless (response_types - SUPPORTED_RESPONSE_TYPES).empty?
        raise ValidationError.new(:invalid_client_metadata, "unsupported response_types: #{(response_types - SUPPORTED_RESPONSE_TYPES).join(",")}")
      end

      if response_types.include?('code') && !grant_types.include?('authorization_code')
        raise ValidationError.new(:invalid_client_metadata, 'response_type "code" requires grant_type "authorization_code"')
      end

      redirect_uris = validate_redirect_uris(metadata[:redirect_uris])

      client_name = metadata[:client_name]&.to_s
      if client_name && client_name.length > MAX_CLIENT_NAME_LENGTH
        raise ValidationError.new(:invalid_client_metadata, "client_name must not exceed #{MAX_CLIENT_NAME_LENGTH} characters")
      end

      client_uri = validate_client_uri(metadata[:client_uri])

      issued_at = now.to_i
      secret = auth_method == 'none' ? nil : SecureRandom.urlsafe_base64(48)

      new(
        id: SecureRandom.urlsafe_base64(24),
        redirect_uris: redirect_uris,
        token_endpoint_auth_method: auth_method,
        grant_types: grant_types,
        response_types: response_types,
        client_name: client_name,
        client_uri: client_uri,
        scope: metadata[:scope]&.to_s,
        secret: secret,
        secret_hash: secret && Digest::SHA384.hexdigest(secret),
        client_id_issued_at: issued_at,
        expiry: issued_at + lifetime,
        registration_ip: registration_ip,
        registration_remote_addr: registration_remote_addr,
        registration_x_forwarded_for: registration_x_forwarded_for,
        ignore_localhost_redirect_uri_port: ignore_localhost_redirect_uri_port,
      )
    end

    def self.validate_redirect_uris(given)
      raise ValidationError.new(:invalid_redirect_uri, 'redirect_uris is required and must be a non-empty array') unless given.is_a?(Array) && !given.empty?
      raise ValidationError.new(:invalid_redirect_uri, "redirect_uris must not exceed #{MAX_REDIRECT_URIS} entries") if given.size > MAX_REDIRECT_URIS

      given.map do |uri|
        str = uri.to_s
        parsed = begin
          Addressable::URI.parse(str)
        rescue Addressable::URI::InvalidURIError
          nil
        end
        raise ValidationError.new(:invalid_redirect_uri, "redirect_uri must not exceed #{MAX_URI_LENGTH} characters") if str.length > MAX_URI_LENGTH
        raise ValidationError.new(:invalid_redirect_uri, "invalid redirect_uri: #{str}") unless parsed&.scheme
        raise ValidationError.new(:invalid_redirect_uri, "redirect_uri must not contain a fragment: #{str}") if parsed.fragment
        raise ValidationError.new(:invalid_redirect_uri, "redirect_uri scheme not allowed: #{str}") if DANGEROUS_REDIRECT_URI_SCHEMES.include?(parsed.scheme.downcase)

        str
      end
    end

    def self.validate_client_uri(given)
      return if given.nil?

      str = given.to_s
      raise ValidationError.new(:invalid_client_metadata, "client_uri must not exceed #{MAX_URI_LENGTH} characters") if str.length > MAX_URI_LENGTH

      parsed = begin
        Addressable::URI.parse(str)
      rescue Addressable::URI::InvalidURIError
        nil
      end
      raise ValidationError.new(:invalid_client_metadata, "invalid client_uri: #{str}") unless parsed&.scheme && parsed.host

      str
    end

    def self.from_json(hash)
      attrs = hash.dup
      attrs.delete(:ttl)
      new(**attrs)
    end

    def initialize(id:, redirect_uris:, token_endpoint_auth_method:, grant_types:, response_types:, client_id_issued_at:, expiry:, secret: nil, secret_hash: nil, client_name: nil, client_uri: nil, scope: nil, preferred_key_group: nil, registration_ip: nil, registration_remote_addr: nil, registration_x_forwarded_for: nil, ignore_localhost_redirect_uri_port: true)
      @id = id
      @redirect_uris = redirect_uris
      @token_endpoint_auth_method = token_endpoint_auth_method
      @grant_types = grant_types
      @response_types = response_types
      @client_id_issued_at = client_id_issued_at
      @expiry = expiry
      @secret = secret
      @secret_hash = secret_hash
      @client_name = client_name
      @client_uri = client_uri
      @scope = scope
      @preferred_key_group = preferred_key_group
      @registration_ip = registration_ip
      @registration_remote_addr = registration_remote_addr
      @registration_x_forwarded_for = registration_x_forwarded_for
      @ignore_localhost_redirect_uri_port = ignore_localhost_redirect_uri_port
    end

    attr_reader :id, :redirect_uris, :token_endpoint_auth_method, :grant_types, :response_types,
      :client_id_issued_at, :expiry, :secret, :secret_hash, :client_name, :client_uri, :scope,
      :preferred_key_group, :registration_ip, :registration_remote_addr, :registration_x_forwarded_for,
      :ignore_localhost_redirect_uri_port

    def confidential?
      token_endpoint_auth_method != 'none'
    end

    # Public clients have no secret to bind the authorization code, so PKCE is mandatory.
    def require_pkce
      !confidential?
    end

    def active?(now = Time.now)
      expiry > now.to_i
    end

    # The client object the OIDC authorization/token endpoints consume. Dynamic records carry
    # no name (so operator rules keyed on name never match them) and pass through the secret
    # hash only for confidential clients. skip_consent defaults to false and is supplied by the
    # provider from the DynamicClients middleware option.
    def to_client_registration(skip_consent: false)
      ClientRegistration.new(
        id: id,
        redirect_uris: redirect_uris,
        secret_hash: confidential? ? secret_hash : nil,
        preferred_key_group: preferred_key_group,
        require_pkce: require_pkce,
        confidential: confidential?,
        ignore_localhost_redirect_uri_port: ignore_localhost_redirect_uri_port,
        skip_consent: skip_consent,
      )
    end

    def as_log
      {
        id: id,
        token_endpoint_auth_method: token_endpoint_auth_method,
        redirect_uris: redirect_uris,
        grant_types: grant_types,
        response_types: response_types,
        client_name: client_name,
        client_uri: client_uri,
        scope: scope,
        client_id_issued_at: client_id_issued_at,
        expiry: expiry,
        dynamic: true,
      }
    end

    def as_json
      {
        id: id,
        secret_hash: secret_hash,
        redirect_uris: redirect_uris,
        grant_types: grant_types,
        response_types: response_types,
        token_endpoint_auth_method: token_endpoint_auth_method,
        client_name: client_name,
        client_uri: client_uri,
        scope: scope,
        preferred_key_group: preferred_key_group,
        client_id_issued_at: client_id_issued_at,
        expiry: expiry,
        ttl: expiry,
        registration_ip: registration_ip,
        registration_remote_addr: registration_remote_addr,
        registration_x_forwarded_for: registration_x_forwarded_for,
        ignore_localhost_redirect_uri_port: ignore_localhost_redirect_uri_port,
      }
    end

    # RFC 7591 §3.2.1 client information response. Includes client_secret only when freshly
    # generated (the plaintext is never persisted, so it is available only right after register).
    def registration_response
      response = {
        client_id: id,
        client_id_issued_at: client_id_issued_at,
        redirect_uris: redirect_uris,
        grant_types: grant_types,
        response_types: response_types,
        token_endpoint_auth_method: token_endpoint_auth_method,
        client_name: client_name,
        client_uri: client_uri,
        scope: scope,
      }.compact

      if confidential? && secret
        response[:client_secret] = secret
        response[:client_secret_expires_at] = expiry
      end

      response
    end
  end
end
