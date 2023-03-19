# config.ru
require 'open-uri'
require 'omniauth'
require 'omniauth-oauth2'
require 'sinatra/base'
require 'rack/session/cookie'
require 'jwt'

module OmniAuth
  module Strategies
    class Himari < OmniAuth::Strategies::OAuth2
      option :name, 'himari'
      option(:client_options, {
        site: 'http://localhost:3000',
        authorize_url: '/oidc/authorize',
        token_url: '/public/oidc/token',
      })
      option :pkce, true

      uid { raw_info['sub'] }

      info do
        { name: raw_info['preferred_username'] }
      end

      extra do
        id_token = access_token['id_token']
        token_payload = JWT.decode(
          id_token,
          nil,
          true,
          algorithms: jwks.map { |k| k[:alg] }.compact.uniq,
          jwks: jwks,
          verify_aud: true,
          aud: options.client_id,
          verify_iss: true,
          iss: options.client_options[:site],
          verify_expiration: true,
        )

        {
          id_info: token_payload,
          raw_info: raw_info,
          id_token_raw: id_token,
        }
      end

      def callback_url
        options[:redirect_uri] || (full_host + callback_path) # https://github.com/omniauth/omniauth-oauth2/pull/142
      end

      def jwks
        @jwks ||= JWT::JWK::Set.new(JSON.parse(URI.open("#{options.client_options[:site]}/public/jwks", 'r', &:read))).tap do |set|
          set.filter! { |k| k[:use] == 'sig' }
        end
      end

      def raw_info
        @raw_info ||= access_token.get('/public/oidc/userinfo').parsed
      end

      def authorize_params
        super.tap do |params|
          params[:scope] = 'openid'
        end
      end
    end
  end
end

class App < Sinatra::Base
  set :protection, use: %i(authenticity_token), except: %i(remote_token)

  get '/' do
    content_type :html
    "<form action=/auth/himari method=POST><input type=hidden name='authenticity_token' value='#{Rack::Protection::AuthenticityToken.token(session)}'><button>Log in</button></form>"
  end

  cb = proc do
    content_type :json
    pp request.env['omniauth.auth']
    JSON.pretty_generate(request.env['omniauth.auth'])
  end
  get '/auth/himari/callback', &cb
  post '/auth/himari/callback', &cb
end


use(Rack::Session::Cookie,
  key: 'rp_session',
  path: '/',
  expire_after: 3600,
  #secure: true,
  secret: SecureRandom.hex(32),
)

use OmniAuth::Builder do
  provider :himari, {
    name: :himari,
    client_id: 'myclient1',
    client_secret: 'himitsudayo1',
    client_options: {

    }
  }
end


run App
