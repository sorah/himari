# frozen_string_literal: true

require 'sinatra/base'
require 'addressable'
require 'base64'

require 'himari/version'

require 'himari/log_line'

require 'himari/token_string'
require 'himari/provider_chain'

require 'himari/authorization_code'
require 'himari/session_data'

require 'himari/middlewares/client'
require 'himari/middlewares/config'
require 'himari/middlewares/signing_key'
require 'himari/middlewares/dynamic_clients'
require 'himari/middlewares/metadata_clients'

require 'himari/services/downstream_authorization'
require 'himari/services/upstream_authentication'

require 'himari/services/client_registration_endpoint'
require 'himari/services/jwks_endpoint'
require 'himari/services/oidc_authorization_endpoint'
require 'himari/services/oidc_provider_metadata_endpoint'
require 'himari/services/oidc_token_endpoint'
require 'himari/services/oidc_userinfo_endpoint'

module Himari
  class App < Sinatra::Base
    set :root, File.expand_path(File.join(__dir__, '..', '..'))

    # remote_token: disabled in favor of authenticity_token (more stricter)
    # json_csrf: can be prevented using x-content-type-options:nosniff
    set :protection, use: %i(authenticity_token), except: %i(remote_token json_csrf)
    set :host_authorization, {}

    set :logging, nil

    ProviderCandidate = Struct.new(:name, :button, :action, keyword_init: true)

    class InvalidSessionToken < StandardError; end

    helpers do
      def current_user
        return @current_user if defined? @current_user

        given_token = session[:himari_session]
        return unless given_token

        given_parsed_token = Himari::SessionData.parse(given_token)

        token = config.storage.find_session(given_parsed_token.handle)
        raise InvalidSessionToken, "no session found in storage (possibly expired)" unless token

        token.verify!(secret: given_parsed_token.secret)

        @current_user = token
      rescue InvalidSessionToken, Himari::TokenString::Error => e
        logger&.warn(Himari::LogLine.new('invalid session token given', req: request_as_log, err: e.class.inspect))
        session.delete(:himari_session)
        nil
      end

      def config
        env[Himari::Middlewares::Config::RACK_KEY]
      end

      def signing_key_provider
        Himari::ProviderChain.new(request.env[Himari::Middlewares::SigningKey::RACK_KEY] || [])
      end

      def client_provider
        Himari::ProviderChain.new(request.env[Himari::Middlewares::Client::RACK_KEY] || [])
      end

      def dynamic_clients_enabled?
        request.env.key?(Himari::Middlewares::DynamicClients::RACK_KEY)
      end

      def metadata_clients_enabled?
        request.env.key?(Himari::Middlewares::MetadataClients::RACK_KEY)
      end

      def known_providers
        back_to = if request.query_string.empty?
          request.path
        else
          Addressable::URI.parse(request.fullpath).tap do |u|
            # Drop only the prompt values that would re-trigger the login screen once the user
            # comes back authenticated (otherwise we'd loop); keep the rest (e.g. consent) so they
            # still apply at the authorize endpoint after login.
            u.query_values = u.query_values.filter_map do |k, v|
              next [k, v] unless k == 'prompt'

              remaining = v.to_s.split(/\s+/) - %w(login select_account)
              [k, remaining.join(' ')] unless remaining.empty?
            end.to_h
          end.to_s
        end
        query = Addressable::URI.form_encode(back_to: back_to)

        config.providers.map do |pr|
          name = pr.fetch(:name)
          ProviderCandidate.new(
            name: name,
            button: pr[:button] || "Log in with #{name}",
            action: "/auth/#{name}?#{query}",
          )
        end
      end

      def csrf_token_value
        Rack::Protection::AuthenticityToken.token(session)
      end

      def csrf_token_name
        'authenticity_token'
      end

      def cachebuster
        env['himari.cachebuster'] ||= Base64.urlsafe_encode64(release_code, padding: false)
      end

      def release_code
        env['himari.release'] ||= [
          Himari::VERSION,
          config.release_fragment,
        ].compact.join(':')
      end

      def request_id
        env['HTTP_X_REQUEST_ID'] ||= SecureRandom.uuid
      end

      def request_as_log
        env['himari.request_as_log'] ||= {
          id: request_id,
          method: request.request_method,
          path: request.path,
          ip: request.ip,
          cip: env['REMOTE_ADDR'],
          xff: env['HTTP_X_FORWARDED_FOR'],
        }
      end

      def msg(key, default = nil)
        config.custom_messages[key] || default
      end

      include ERB::Util
    end

    before do
      request_as_log
    end

    get '/' do
      content_type :text
      "Himari #{release_code}\n"
    end

    # Served on GET (initial request and consent display) and POST (consent submission). The
    # consent form posts the original authorization params back here as hidden fields plus a
    # _consent decision; everything else flows through OidcAuthorizationEndpoint identically.
    authorize_ep = proc do
      client = client_provider.find(id: params[:client_id])
      unless client
        logger&.warn(Himari::LogLine.new('authorize: no client registration found', req: request_as_log, client_id: params[:client_id]))
        next halt 401, 'unknown client'
      end

      if current_user
        # do downstream authz and process oidc request. The OIDC request's scope is parsed the
        # same way rack-oauth2 parses it downstream (OidcAuthorizationEndpoint), so the scopes the
        # authz rules see match those the grant is filtered to.
        requested_scopes = request.params['scope'].to_s.split(' ')
        decision = Himari::Services::DownstreamAuthorization.from_request(session: current_user, client: client, request: request, requested_scopes: requested_scopes).perform
        logger&.info(Himari::LogLine.new('authorize: downstream authorized', req: request_as_log, session: current_user.as_log, allowed: decision.authz_result.allowed, result: decision.as_log))
        raise unless decision.authz_result.allowed # sanity check

        authz = AuthorizationCode.make(
          client_id: decision.client.id,
          claims: decision.claims,
          lifetime: decision.lifetime,
          mint_jwt_access_token: decision.mint_jwt_access_token,
          session_handle: current_user.handle,
        )

        consent = case params[:_consent]
        when 'approve' then :approve
        when 'deny' then :deny
        end

        Himari::Services::OidcAuthorizationEndpoint.new(
          authz: authz,
          client: client,
          storage: config.storage,
          issuer: config.issuer,
          consent: consent,
          logger: logger,
        ).call(env)
      else
        logger&.info(Himari::LogLine.new('authorize: prompt login', req: request_as_log, client_id: params[:client_id]))
        erb(config.custom_templates[:login] || :login)
      end
    rescue Himari::Services::OidcAuthorizationEndpoint::ReauthenticationRequired
      logger&.warn(Himari::LogLine.new('authorize: prompt login to reauthenticate (demanded by oidc request)', req: request_as_log, session: current_user&.as_log, allowed: decision&.authz_result&.allowed, result: decision&.as_log))
      next erb(config.custom_templates[:login] || :login)
    rescue Himari::Services::OidcAuthorizationEndpoint::ConsentRequired => e
      logger&.info(Himari::LogLine.new('authorize: prompt consent', req: request_as_log, session: current_user&.as_log, client: e.client.as_log, scopes: e.scopes))
      @consent_client = e.client
      @consent_scopes = e.scopes
      next erb(config.custom_templates[:consent] || :consent)
    rescue Himari::Services::DownstreamAuthorization::ForbiddenError => e
      logger&.warn(Himari::LogLine.new('authorize: downstream forbidden', req: request_as_log, session: current_user&.as_log, allowed: e.result.authz_result.allowed, err: e.class.inspect, result: e.as_log))

      @notice = message_human = e.result.authz_result&.user_facing_message

      case e.result.authz_result&.suggestion
      when nil
        # do nothing
      when :reauthenticate
        logger&.warn(Himari::LogLine.new('authorize: prompt login to reauthenticate (suggested by decision)', req: request_as_log, session: current_user&.as_log, allowed: e.result.authz_result.allowed, err: e.class.inspect, result: e.as_log))
        next erb(config.custom_templates[:login] || :login)
      else
        raise ArgumentError, "Unknown suggestion value for DownstreamAuthorization denial; #{e.as_log.inspect}"
      end

      halt(403, "Forbidden#{message_human ? "; #{message_human}" : nil}")
    end
    get '/oidc/authorize', &authorize_ep
    post '/oidc/authorize', &authorize_ep

    token_ep = proc do
      Himari::Services::OidcTokenEndpoint.new(
        client_provider: client_provider,
        signing_key_provider: signing_key_provider,
        storage: config.storage,
        issuer: config.issuer,
        logger: logger,
      ).call(env)
    end
    post '/oidc/token', &token_ep
    post '/public/oidc/token', &token_ep

    userinfo_ep = proc do
      Himari::Services::OidcUserinfoEndpoint.new(
        storage: config.storage,
        signing_key_provider: signing_key_provider,
        logger: logger,
      ).call(env)
    end
    get '/oidc/userinfo', &userinfo_ep
    get '/public/oidc/userinfo', &userinfo_ep
    post '/oidc/userinfo', &userinfo_ep
    post '/public/oidc/userinfo', &userinfo_ep

    jwks_ep = proc do
      Himari::Services::JwksEndpoint.new(
        signing_key_provider: signing_key_provider,
      ).call(env)
    end
    get '/jwks', &jwks_ep
    get '/public/jwks', &jwks_ep

    # RFC 7591 Dynamic Client Registration. Enabled by presence of the DynamicClients
    # middleware; the route always exists but 404s when the feature is off.
    register_ep = proc do
      next halt 404, 'not found' unless dynamic_clients_enabled?

      Himari::Services::ClientRegistrationEndpoint.new(
        storage: config.storage,
        registration_lifetime: request.env[Himari::Middlewares::DynamicClients::RACK_KEY].registration_lifetime,
        ignore_localhost_redirect_uri_port: request.env[Himari::Middlewares::DynamicClients::RACK_KEY].ignore_localhost_redirect_uri_port,
        logger: logger,
      ).call(env)
    end
    post '/oidc/register', &register_ep
    post '/public/oidc/register', &register_ep
    # Wire the non-POST verbs too so they reach the endpoint, which answers 405 (RFC 7591 only
    # defines POST). Without these Sinatra would 404 a GET, masking the method error.
    %w(/oidc/register /public/oidc/register).each do |path|
      get(path, &register_ep)
      put(path, &register_ep)
      patch(path, &register_ep)
      delete(path, &register_ep)
    end

    metadata_ep = proc do
      Himari::Services::OidcProviderMetadataEndpoint.new(
        signing_key_provider: signing_key_provider,
        issuer: config.issuer,
        registration_endpoint: dynamic_clients_enabled? ? "#{config.issuer}/public/oidc/register" : nil,
        client_id_metadata_document_supported: metadata_clients_enabled?,
        scopes_supported: config.scopes_supported,
        claims_supported: config.claims_supported,
      ).call(env)
    end
    # OpenID Connect Discovery 1.0
    get '/.well-known/openid-configuration', &metadata_ep
    # RFC 8414 OAuth 2.0 Authorization Server Metadata
    get '/.well-known/oauth-authorization-server', &metadata_ep

    omniauth_callback = proc do
      authhash = request.env['omniauth.auth']
      next halt(400, 'Bad Request') unless authhash

      # do upstream auth
      authn = Himari::Services::UpstreamAuthentication.from_request(request).perform
      logger&.info(Himari::LogLine.new('authentication allowed', req: request_as_log, allowed: authn.authn_result.allowed, uid: authhash[:uid], provider: authhash[:provider], result: authn.as_log, existing_session: current_user&.as_log))
      raise unless authn.authn_result.allowed # sanity check

      given_back_to = request.env['omniauth.params']&.fetch('back_to', nil)
      back_to = if given_back_to
                  uri = begin
                    Addressable::URI.parse(given_back_to)
                  rescue Addressable::URI::InvalidURIError
                    nil
                  end
                  if uri && uri.host.nil? && uri.scheme.nil? && uri.path.start_with?('/')
                    given_back_to
                  else
                    logger&.warn(Himari::LogLine.new('invalid back_to', req: request_as_log, given_back_to: given_back_to))
                    nil
                  end
      end || '/'

      session.destroy

      new_session = authn.session_data
      config.storage.put_session(new_session)
      session[:himari_session] = new_session.format.to_s

      redirect back_to
    rescue Himari::Services::UpstreamAuthentication::UnauthorizedError => e
      logger&.warn(Himari::LogLine.new('authentication denied', req: request_as_log, err: e.class.inspect, allowed: e.result.authn_result.allowed, uid: request.env.fetch('omniauth.auth')[:uid], provider: request.env.fetch('omniauth.auth')[:provider], result: e.as_log, existing_session: current_user&.as_log))
      message_human = e.result.authn_result&.user_facing_message
      halt(401, "Unauthorized#{message_human ? "; #{message_human}" : nil}")
    end
    get '/auth/:provider/callback', &omniauth_callback
    post '/auth/:provider/callback', &omniauth_callback
  end
end
