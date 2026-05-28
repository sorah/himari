# frozen_string_literal: true

require 'httpx'

require 'himari/version'
require 'himari/item_providers/oauth_client_metadata'
require 'himari/middlewares/client'
require 'himari/middlewares/config'

module Himari
  module Middlewares
    # Enables OAuth Client ID Metadata Document support
    # (draft-ietf-oauth-client-id-metadata-document). Its presence in the Rack env (RACK_KEY)
    # advertises support in the discovery documents. It appends a single, long-lived
    # OauthClientMetadata provider to the client chain (Middlewares::Client::RACK_KEY) so URL
    # client_ids resolve through the same client_provider.find(id:) lookup the OIDC endpoints
    # already use; the provider retains its HTTPX session and document cache across requests.
    #
    # Must be placed after Middlewares::Config.
    #
    # Options:
    # - allowed_client_ids [Array<String, Regexp>] empty (default) accepts any compliant https
    #   URL; otherwise a client_id must match an entry (String exact, Regexp =~).
    # - require_pkce [Boolean] force PKCE for metadata clients (default true; they are public).
    # - ssrf [true, false, Hash] SSRF filtering. true (default) restricts to https; a Hash is
    #   merged into the ssrf_filter plugin options (e.g. allowed_schemes); false disables it
    #   (only for an authorization server running on a loopback address).
    # - user_agent [String] User-Agent header for fetches.
    # - http_timeout [Hash] HTTPX timeout options.
    # - max_response_size [Integer] reject documents larger than this many bytes (default 5 KiB).
    # - cache_min_ttl / cache_max_ttl / cache_default_ttl [Integer] cache bounds in seconds.
    # - cache_max_total_size [Integer] approximate cap on total cached document bytes; the oldest
    #   entries are evicted once exceeded (default 1 MiB).
    class MetadataClients
      RACK_KEY = 'himari.metadata_clients'

      DEFAULT_USER_AGENT = "Himari-OauthClientMetadataFetch/#{Himari::VERSION} (+https://github.com/sorah/himari)"
      DEFAULT_HTTP_TIMEOUT = {connect_timeout: 5, request_timeout: 10}.freeze

      Options = Data.define(:allowed_client_ids, :require_pkce, :ssrf, :user_agent, :http_timeout, :max_response_size, :cache_min_ttl, :cache_max_ttl, :cache_default_ttl, :cache_max_total_size)

      def initialize(app, kwargs = {})
        @app = app
        @options = Options.new(
          allowed_client_ids: kwargs.fetch(:allowed_client_ids, []),
          require_pkce: kwargs.fetch(:require_pkce, true),
          ssrf: kwargs.fetch(:ssrf, true),
          user_agent: kwargs.fetch(:user_agent, DEFAULT_USER_AGENT),
          http_timeout: kwargs.fetch(:http_timeout, DEFAULT_HTTP_TIMEOUT),
          max_response_size: kwargs.fetch(:max_response_size, 5120),
          cache_min_ttl: kwargs.fetch(:cache_min_ttl, 60),
          cache_max_ttl: kwargs.fetch(:cache_max_ttl, 86400),
          cache_default_ttl: kwargs.fetch(:cache_default_ttl, 300),
          cache_max_total_size: kwargs.fetch(:cache_max_total_size, 1_048_576),
        )
        @provider = Himari::ItemProviders::OauthClientMetadata.new(
          session: build_session(@options),
          allowed_client_ids: @options.allowed_client_ids,
          require_pkce: @options.require_pkce,
          max_response_size: @options.max_response_size,
          cache_min_ttl: @options.cache_min_ttl,
          cache_max_ttl: @options.cache_max_ttl,
          cache_default_ttl: @options.cache_default_ttl,
          cache_max_total_size: @options.cache_max_total_size,
          logger: kwargs[:logger],
        )
      end

      attr_reader :app, :options

      def call(env)
        config = env[Himari::Middlewares::Config::RACK_KEY]
        raise "Himari::Middlewares::MetadataClients must be placed after Himari::Middlewares::Config" unless config

        env[RACK_KEY] = @options
        env[Himari::Middlewares::Client::RACK_KEY] ||= []
        env[Himari::Middlewares::Client::RACK_KEY] += [@provider]

        @app.call(env)
      end

      # Build a persistent, SSRF-filtered HTTPX session. Notably it does not enable the
      # follow_redirects plugin: the draft requires redirects not be followed.
      private def build_session(options)
        session = HTTPX.plugin(:persistent)
        session = case options.ssrf
        when true
          session.plugin(:ssrf_filter, allowed_schemes: %w(https))
        when Hash
          ssrf_options = {allowed_schemes: %w(https)}.merge(options.ssrf)
          session.plugin(:ssrf_filter, **ssrf_options)
        when false
          session
        else
          raise ArgumentError, "ssrf option must be true, false, or a Hash"
        end
        session.with(
          headers: {'user-agent' => options.user_agent, 'accept' => 'application/json'},
          timeout: options.http_timeout,
        )
      end
    end
  end
end
