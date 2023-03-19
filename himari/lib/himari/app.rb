require 'sinatra/base'
require 'addressable'

require 'himari/provider_chain'
require 'himari/authorization_code'

require 'himari/middlewares/client'
require 'himari/middlewares/config'
require 'himari/middlewares/signing_key'

require 'himari/services/downstream_authorization'
require 'himari/services/upstream_authentication'

require 'himari/services/jwks_endpoint'
require 'himari/services/oidc_authorization_endpoint'
require 'himari/services/oidc_provider_metadata_endpoint'
require 'himari/services/oidc_token_endpoint'
require 'himari/services/oidc_userinfo_endpoint'


module Himari
  class App < Sinatra::Base
    set :root, File.expand_path(File.join(__dir__, '..', '..'))

    set :protection, use: %i(authenticity_token), except: %i(remote_token)

    ProviderCandidate = Struct.new(:name, :button, :action, keyword_init: true)

    helpers do
      def current_user
        session[:session_data]
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

      def known_providers
        query = Addressable::URI.form_encode(back_to: request.fullpath)
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
        env['himari.cachebuster'] || "#{Process.pid}"
      end
    end

    get '/' do
      content_type :text
      "Himari\n"
    end

    get '/oidc/authorize' do
      client = client_provider.find(id: params[:client_id]) { |c,h| c.match_hint?(**h) }
      next halt 401, 'unknown client' unless client
      if current_user
        # do downstream authz and process oidc request
        decision = Himari::Services::DownstreamAuthorization.from_request(session: current_user, client: client, request: request).perform
        raise unless decision.authz_result.allowed # sanity check

        authz = AuthorizationCode.make(
          client_id: decision.client.id,
          claims: decision.claims,
        )

        Himari::Services::OidcAuthorizationEndpoint.new(
          authz: authz,
          client: client,
          storage: config.storage,
        ).app.call(env)
      else
        erb :login
      end
    rescue Himari::Services::DownstreamAuthorization::ForbiddenError
      halt 403, "Forbidden"
    end

    token_ep = proc do
      Himari::Services::OidcTokenEndpoint.new(
        client_provider: client_provider,
        signing_key_provider: signing_key_provider,
        storage: config.storage,
        issuer: config.issuer,
      ).app.call(env)
    end
    post '/oidc/token', &token_ep
    post '/public/oidc/token', &token_ep

    userinfo_ep = proc do
      Himari::Services::OidcUserinfoEndpoint.new(
        storage: config.storage,
      ).call(env)
    end
    get '/oidc/userinfo', &userinfo_ep
    get '/public/oidc/userinfo', &userinfo_ep


    jwks_ep = proc do
      Himari::Services::JwksEndpoint.new(
        signing_key_provider: signing_key_provider,
      ).call(env)
    end
    get '/jwks', &jwks_ep
    get '/public/jwks', &jwks_ep

    get '/.well-known/openid-configuration' do
      Himari::Services::OidcProviderMetadataEndpoint.new(
        signing_key_provider: signing_key_provider,
        issuer: config.issuer,
      ).call(env)
    end

    omniauth_callback = proc do
      # do upstream auth
      authn = Himari::Services::UpstreamAuthentication.from_request(request).perform
      raise unless authn.authn_result.allowed # sanity check

      given_back_to = request.env['omniauth.params']&.fetch('back_to', nil)
      p given_back_to
      back_to = if given_back_to
        uri = Addressable::URI.parse(given_back_to)
        if uri && uri.host.nil? && uri.scheme.nil? && uri.path.start_with?('/')
          given_back_to
        end
      end || '/'

      session.destroy
      session[:session_data] = authn.session_data
      redirect back_to
    rescue Himari::Services::UpstreamAuthentication::UnauthorizedError
      halt(401, 'Unauthorized')
    end
    get '/auth/:provider/callback', &omniauth_callback
    post '/auth/:provider/callback', &omniauth_callback
  end
end
