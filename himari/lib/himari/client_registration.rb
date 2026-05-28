# frozen_string_literal: true

require 'digest/sha2'
require 'addressable/uri'

module Himari
  class ClientRegistration
    # Loopback hosts whose redirect_uri port may be relaxed (RFC 8252 §7.3,
    # draft-ietf-oauth-v2-1-15 §8.4.2). Addressable returns IPv6 hosts bracketed.
    LOOPBACK_HOSTS = %w[127.0.0.1 [::1] localhost].freeze

    def initialize(id:, redirect_uris:, name: nil, secret: nil, secret_hash: nil, preferred_key_group: nil, require_pkce: false, confidential: true, ignore_localhost_redirect_uri_port: true)
      @name = name
      @id = id
      @secret = secret
      @secret_hash = secret_hash
      @redirect_uris = redirect_uris
      @preferred_key_group = preferred_key_group
      @require_pkce = require_pkce
      @confidential = confidential
      @ignore_localhost_redirect_uri_port = ignore_localhost_redirect_uri_port

      raise ArgumentError, "name starts with '_' is reserved" if @name&.start_with?('_')
      raise ArgumentError, "either secret or secret_hash must be present" if confidential && !@secret && !@secret_hash
    end

    attr_reader :name, :id, :redirect_uris, :preferred_key_group, :require_pkce, :ignore_localhost_redirect_uri_port

    def confidential?
      @confidential
    end

    def secret_hash
      @secret_hash ||= Digest::SHA384.hexdigest(secret)
    end

    def match_secret?(given_secret)
      return false unless confidential? && given_secret

      if @secret
        Rack::Utils.secure_compare(@secret, given_secret)
      else
        dgst = [secret_hash].pack('H*')
        Rack::Utils.secure_compare(dgst, Digest::SHA384.digest(given_secret))
      end
    end

    # True when one of the registered redirect_uris covers the given (request) redirect_uri.
    # draft-ietf-oauth-v2-1-15 §4.1.3 / RFC 3986 §6.2.1: simple (exact) string comparison, with the
    # loopback-port exception of RFC 8252 §7.3 / draft-v2-1 §8.4.2 applied when enabled.
    def redirect_uri_covers?(given)
      given = given.to_s
      return false if given.empty?

      redirect_uris.any? { |registered| redirect_uri_match?(registered.to_s, given) }
    end

    def as_log
      {name: name, id: id}
    end

    def match_hint?(id: nil)
      result = true

      result &&= if id
        id == self.id
      else
        true
      end

      result
    end

    private def redirect_uri_match?(registered, given)
      return true if registered == given
      return false unless ignore_localhost_redirect_uri_port

      reg = loopback_uri(registered) or return false
      giv = loopback_uri(given) or return false

      # Port is intentionally ignored to allow ephemeral loopback ports; fragments are
      # rejected at registration time, so loopback_uri requires their absence here too.
      reg.scheme == giv.scheme && reg.host == giv.host && reg.path == giv.path && reg.query == giv.query
    end

    private def loopback_uri(str)
      uri = begin
        Addressable::URI.parse(str)
      rescue Addressable::URI::InvalidURIError
        nil
      end
      return unless uri && LOOPBACK_HOSTS.include?(uri.host)
      return if uri.fragment

      uri
    end
  end
end
