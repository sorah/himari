# frozen_string_literal: true

require 'omniauth'
require 'omniauth-himari'
require 'sinatra/base'
require 'rack/session/cookie'
require 'jwt'
require 'json'
require 'httpx'

ISSUER = 'http://himari.localhost:1355'
CLIENT_ID = 'myclient1'
CLIENT_SECRET = 'himitsudayo1'

class App < Sinatra::Base
  set :protection, use: %i(authenticity_token), except: %i(remote_token)
  set :host_authorization, {}

  helpers do
    def csrf
      %(<input type="hidden" name="authenticity_token" value="#{Rack::Protection::AuthenticityToken.token(session)}">)
    end

    # A login button; prompt is forwarded to the OP authorize request (the strategy reads
    # request.GET['prompt']), letting you force the consent page on a skip_consent client.
    def login_button(label, prompt: nil)
      action = "/auth/himari#{prompt ? "?prompt=#{prompt}" : ""}"
      %(<form action="#{action}" method=POST style="display:inline">#{csrf}<button>#{Rack::Utils.escape_html(label)}</button></form>)
    end

    def render_signed_in(creds)
      <<~HTML
        <h2>session credentials</h2>
        <pre>#{Rack::Utils.escape_html(JSON.pretty_generate(creds))}</pre>
        <form action=/userinfo method=POST style="display:inline">#{csrf}<button>Call userinfo</button></form>
        <form action=/refresh method=POST style="display:inline">#{csrf}<button>Refresh token</button></form>
        <form action=/logout method=POST style="display:inline">#{csrf}<button>Forget session</button></form>
      HTML
    end

    def render_result(label, body)
      content_type :html
      <<~HTML
        <h1>#{Rack::Utils.escape_html(label)}</h1>
        <pre>#{Rack::Utils.escape_html(body)}</pre>
        <p><a href="/">back</a></p>
      HTML
    end
  end

  get '/' do
    content_type :html
    creds = session[:credentials]
    <<~HTML
      <h1>himari dev RP</h1>
      <p>
        #{login_button("Log in")}
        #{login_button("Log in (prompt=consent)", prompt: "consent")}
      </p>
      #{creds ? render_signed_in(creds) : "<p>not signed in</p>"}
    HTML
  end

  # Keep the session payload minimal: stashing the whole omniauth.auth hash
  # (id_token JWT + raw_info) overflows the 4K Rack::Session::Cookie limit and
  # silently drops the entire session.
  cb = proc do
    auth = request.env['omniauth.auth']
    session[:credentials] = {
      access_token: auth.dig(:credentials, :token),
      refresh_token: auth.dig(:credentials, :refresh_token),
      id_token: auth.dig(:credentials, :id_token),
      expires_at: auth.dig(:credentials, :expires_at),
      sub: auth[:uid],
      name: auth.dig(:info, :name),
    }
    redirect '/'
  end
  get '/auth/himari/callback', &cb
  post '/auth/himari/callback', &cb

  post '/userinfo' do
    creds = session[:credentials] or halt 400, 'not signed in'
    resp = HTTPX.with(headers: {'Authorization' => "Bearer #{creds[:access_token]}"})
      .get("#{ISSUER}/public/oidc/userinfo")
    render_result("userinfo (HTTP #{resp.status})", resp.body.to_s)
  end

  post '/refresh' do
    creds = session[:credentials] or halt 400, 'not signed in'
    halt 400, 'no refresh_token in session' unless creds[:refresh_token]
    resp = HTTPX.post("#{ISSUER}/public/oidc/token", form: {
      grant_type: 'refresh_token',
      refresh_token: creds[:refresh_token],
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
    })
    body = resp.body.to_s
    if resp.status == 200
      parsed = JSON.parse(body, symbolize_names: true)
      session[:credentials] = creds.merge(
        access_token: parsed[:access_token],
        refresh_token: parsed[:refresh_token] || creds[:refresh_token],
        id_token: parsed[:id_token],
        expires_at: parsed[:expires_in] ? Time.now.to_i + parsed[:expires_in] : nil,
      )
    end
    render_result("refresh (HTTP #{resp.status})", body)
  end

  post '/logout' do
    session.destroy
    redirect '/'
  end
end

use(
  Rack::Session::Cookie,
  key: 'rp_session',
  path: '/',
  expire_after: 3600,
  secret: File.read(File.join(__dir__, 'tmp', 'session_secret')),
)

use OmniAuth::Builder do
  provider :himari, {
    name: :himari,
    site: ISSUER,
    client_id: CLIENT_ID,
    client_secret: CLIENT_SECRET,
    scope: 'openid offline_access',
    use_userinfo: true,
  }
end

run App
