# frozen_string_literal: true

require 'json'
require 'time'
require 'addressable/uri'
require 'concurrent/map'
require 'concurrent/atomic/atomic_fixnum'
require 'httpx'

require 'himari/log_line'
require 'himari/item_provider'
require 'himari/client_registration'
require 'himari/dynamic_client_registration'

module Himari
  module ItemProviders
    # Resolves clients whose client_id is an https URL pointing to a JSON client metadata
    # document, per draft-ietf-oauth-client-id-metadata-document. When the OIDC endpoints look
    # a client up by id, this provider fetches and validates that document on demand and
    # presents it as a public ClientRegistration.
    #
    # The HTTPX session is built once and retained for connection reuse; successful documents
    # are cached in-memory (respecting HTTP cache headers within configured bounds). Errors and
    # malformed documents are never cached, and the provider always fails closed (returns []),
    # so a fetch problem surfaces as an unknown client rather than an exception.
    class OauthClientMetadata
      include Himari::ItemProvider

      class FetchError < StandardError; end
      class InvalidDocument < StandardError; end

      CacheEntry = Struct.new(:value, :expires_at, :size, :seq)

      # @param session [HTTPX::Session] persistent, SSRF-filtered session (built by the middleware)
      # @param allowed_client_ids [Array<String, Regexp>] empty = allow any compliant https URL
      def initialize(session:, allowed_client_ids: [], require_pkce: true, ignore_localhost_redirect_uri_port: true,
        skip_consent: false, scopes: Himari::ClientRegistration::IMPLICIT_SCOPES,
        max_response_size: 5120,
        cache_min_ttl: 60, cache_max_ttl: 86400, cache_default_ttl: 300, cache_max_total_size: 1_048_576, logger: nil)
        @session = session
        @allowed_client_ids = allowed_client_ids
        @require_pkce = require_pkce
        @ignore_localhost_redirect_uri_port = ignore_localhost_redirect_uri_port
        @skip_consent = skip_consent
        @scopes = scopes
        @max_response_size = max_response_size
        @cache_min_ttl = cache_min_ttl
        @cache_max_ttl = cache_max_ttl
        @cache_default_ttl = cache_default_ttl
        @cache_max_total_size = cache_max_total_size
        @logger = logger
        @cache = Concurrent::Map.new
        @cache_total_size = Concurrent::AtomicFixnum.new(0)
        @cache_seq = Concurrent::AtomicFixnum.new(0)
      end

      def collect(id: nil, **_hint)
        return [] unless id.is_a?(String)
        return [] unless compliant_client_id_url?(id)
        return [] unless allowed?(id)

        cached = cache_get(id)
        return [cached] if cached

        registration, ttl, size = fetch_and_build(id)
        cache_put(id, registration, ttl, size) if ttl.positive?
        [registration]
      rescue HTTPX::Error, FetchError, InvalidDocument, JSON::ParserError, Himari::DynamicClientRegistration::ValidationError => e
        @logger&.warn(Himari::LogLine.new('OauthClientMetadata: client_id rejected', client_id: id, error: e.message))
        []
      end

      private def compliant_client_id_url?(id)
        uri = begin
          Addressable::URI.parse(id)
        rescue Addressable::URI::InvalidURIError
          nil
        end
        return false unless uri
        return false unless uri.scheme == 'https'
        return false if uri.fragment
        return false if uri.user || uri.password

        path = uri.path
        return false if path.nil? || path.empty?
        return false if path.split('/').any? { |seg| seg == '.' || seg == '..' }

        true
      end

      private def allowed?(id)
        return true if @allowed_client_ids.empty?

        @allowed_client_ids.any? do |matcher|
          matcher.is_a?(Regexp) ? matcher.match?(id) : matcher.to_s == id
        end
      end

      private def fetch_and_build(url)
        # stream: true must be passed to the request (not preset on the session via .with, which
        # would yield an already-buffered Response with no #each). It returns a StreamResponse:
        # status and headers are inspected first, then the body is consumed under a hard byte cap
        # below, without buffering the whole body up front.
        resp = @session.get(url, stream: true)
        # Surfaces transport/SSRF failures (HTTPX::Error) and HTTP >= 400. The draft also forbids
        # following redirects, so anything other than 200 (including 3xx) is an error too.
        resp.raise_for_status
        raise FetchError, "unexpected status: #{resp.status}" unless resp.status == 200

        content_length = resp.headers['content-length']
        raise FetchError, 'response exceeds maximum size' if content_length && content_length.to_i > @max_response_size
        raise FetchError, 'unexpected content-type' unless json_content_type?(resp.headers['content-type'])

        body = read_capped_body(resp)

        doc = JSON.parse(body, symbolize_names: true)
        registration = build_registration(doc, url)
        # The whole document is safe to log: it is size-capped and client_secret* is rejected.
        @logger&.info(Himari::LogLine.new('OauthClientMetadata: fetched', client_id: url, metadata: doc))
        [registration, compute_ttl(resp), body.bytesize]
      end

      # Stream the body and abort as soon as it exceeds the cap. The client_id URL is
      # attacker-influenced and HTTPX has no hard body limit, so a malicious host could omit
      # Content-Length and stream an unbounded response; capping during the read (rather than
      # after buffering the whole body) prevents that memory/disk exhaustion.
      #
      # FIXME: this streaming read is a workaround for the lack of a built-in maximum body size in
      # HTTPX. Replace it with a native body cap once available:
      # https://gitlab.com/os85/httpx/-/work_items/383
      private def read_capped_body(resp)
        body = +''
        resp.each do |chunk|
          body << chunk
          raise FetchError, 'response exceeds maximum size' if body.bytesize > @max_response_size
        end
        body
      end

      private def build_registration(doc, url)
        raise InvalidDocument, 'document must be a JSON object' unless doc.is_a?(Hash)
        raise InvalidDocument, 'client_id does not match document URL' unless doc[:client_id] == url
        raise InvalidDocument, 'client_secret must not be present' if doc.key?(:client_secret) || doc.key?(:client_secret_expires_at)

        auth_method = doc[:token_endpoint_auth_method]
        raise InvalidDocument, "token_endpoint_auth_method must be 'none'" if auth_method && auth_method.to_s != 'none'

        redirect_uris = Himari::DynamicClientRegistration.validate_redirect_uris(doc[:redirect_uris])

        Himari::ClientRegistration.new(
          id: url,
          redirect_uris: redirect_uris,
          confidential: false,
          require_pkce: @require_pkce,
          ignore_localhost_redirect_uri_port: @ignore_localhost_redirect_uri_port,
          skip_consent: @skip_consent,
          scopes: @scopes,
        )
      end

      private def json_content_type?(value)
        type = value.to_s.split(';', 2).first.to_s.strip.downcase
        type == 'application/json' || type.end_with?('+json')
      end

      # Honour Cache-Control/Expires within configured bounds. no-store/no-cache disables caching.
      private def compute_ttl(resp)
        cache_control = resp.headers['cache-control'].to_s.downcase
        return 0 if cache_control.include?('no-store') || cache_control.include?('no-cache')

        ttl = if (m = cache_control.match(/max-age\s*=\s*(\d+)/))
          m[1].to_i
        elsif (expires = resp.headers['expires'])
          parsed = begin
            Time.httpdate(expires)
          rescue ArgumentError
            nil
          end
          parsed && (parsed - Time.now).to_i
        end

        (ttl || @cache_default_ttl).clamp(@cache_min_ttl, @cache_max_ttl)
      end

      private def cache_get(id)
        entry = @cache[id]
        return unless entry
        return entry.value if entry.expires_at > Time.now.to_f

        forget(id, entry)
        nil
      end

      private def cache_put(id, value, ttl, size)
        entry = CacheEntry.new(value, Time.now.to_f + ttl, size, @cache_seq.increment)
        previous = @cache[id]
        @cache[id] = entry
        delta = size - (previous&.size || 0)
        @cache_total_size.update { |total| total + delta }
        evict_until_within_limit
      end

      # Drop the oldest (lowest seq) entries until the tracked total body size fits the limit.
      # Sizes are approximate (original JSON body bytes); concurrent eviction may overshoot a
      # little, which is acceptable for a cache.
      private def evict_until_within_limit
        while @cache_total_size.value > @cache_max_total_size
          oldest = @cache.each_pair.min_by { |_id, entry| entry.seq }
          break unless oldest

          forget(*oldest)
        end
      end

      private def forget(id, entry)
        return unless @cache.delete_pair(id, entry)

        @cache_total_size.update { |total| total - entry.size }
      end
    end
  end
end
