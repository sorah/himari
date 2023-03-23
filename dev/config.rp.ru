# config.ru
require 'open-uri'
require 'omniauth'
require 'omniauth-himari'
require 'sinatra/base'
require 'rack/session/cookie'
require 'jwt'

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
    site: 'http://localhost:3000',
    client_id: 'myclient1',
    client_secret: 'himitsudayo1',
    use_userinfo: true,
  }
end


run App
