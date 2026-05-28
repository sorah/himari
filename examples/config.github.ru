# frozen_string_literal: true

# config.ru
require 'himari'
require 'himari/aws'
require 'json'
require 'omniauth'
require 'omniauth-github'
require 'rack'
require 'rack/session/cookie'
require 'faraday'

use(
  Rack::Session::Cookie,
  path: '/',
  expire_after: 3600,
  secure: true,
  secret: ENV.fetch('SECRET_KEY_BASE'),
)

use OmniAuth::Builder do
  # NOTE: Plain GitHub OAuth Apps don't issue refresh tokens. To exercise the
  # refresh_token grant against GitHub, this must be a GitHub *App* with
  # user-token expiration enabled and registered as an OmniAuth provider that
  # surfaces credentials.refresh_token (e.g. omniauth-github with appropriate
  # scopes + GitHub App).
  provider :github,
    ENV.fetch('GITHUB_CLIENT_ID'),
    ENV.fetch('GITHUB_CLIENT_SECRET'),
    scope: 'read:org'
end

GH_TOKEN_URL = 'https://github.com/login/oauth/access_token'
gh_oauth = Faraday.new(url: 'https://github.com') do |b|
  b.request :url_encoded
  b.headers['Accept'] = 'application/json'
  b.response :json
end
gh_api = Faraday.new(url: 'https://api.github.com') do |b|
  b.response :json
  b.response :raise_error
end

# Exchange a stored upstream refresh_token for fresh credentials.
# Returns the response body or nil if GitHub refuses the refresh (revoked,
# expired, etc.).
gh_exchange = ->(refresh_token) do
  resp = gh_oauth.post(
    '/login/oauth/access_token',
    grant_type: 'refresh_token',
    refresh_token: refresh_token,
    client_id: ENV.fetch('GITHUB_CLIENT_ID'),
    client_secret: ENV.fetch('GITHUB_CLIENT_SECRET'),
  )
  resp.body['access_token'] ? resp.body : nil
end

use(
  Himari::Middlewares::Config,
  issuer: 'https://idp.example.net',
  providers: [
    {name: :github, button: 'Log in with GitHub'},
  ],
  storage: Himari::Storages::Filesystem.new('/var/lib/himari/data'),
)

# Signing key
use(
  Himari::Middlewares::SigningKey,
  id: 'key1', # kid
  pkey: OpenSSL::PKey::RSA.new(File.read('...'), ''),
)

# Add clients as many as you need
use(
  Himari::Middlewares::Client,
  name: 'awsalb', # friendly name (this can be referenced from policies)
  id: '...',
  secret_hash: '...', # Digest::SHA384.hexdigest of actual secret
  redirect_uris: %w(https://app.example.net/oauth2/idpresponse),
)

# Initial sign-in only: stash upstream credentials in refresh_info and
# identity in claims/user_data.
use(Himari::Middlewares::ClaimsRule, name: 'github-initialize') do |context, decision|
  next decision.skip! unless context.initial?
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  decision.initialize_claims!(
    sub: "github_#{context.auth[:uid]}",
    name: context.auth[:info][:nickname],
    preferred_username: context.auth[:info][:nickname],
    email: context.auth[:info][:email],
  )
  # user_data[:provider] is load-bearing — Claims::Context#provider falls back
  # to session.user_data[:provider] on the refresh path.
  decision.user_data[:provider] = 'github'
  decision.refresh_info = {
    provider: 'github',
    sub: decision.claims[:sub],
    nickname: context.auth[:info][:nickname],
    email: context.auth[:info][:email],
    refresh_token: context.auth[:credentials][:refresh_token],
    access_token: context.auth[:credentials][:token],
    access_token_expires_at: context.auth[:credentials][:expires_at],
  }

  decision.continue!
end

# Refresh only: exchange the stored upstream refresh_token, rebuild identity
# claims from refresh_info, rotate the stored credentials. A definite deny
# here maps to invalid_grant + refresh-token revocation at the token endpoint.
use(Himari::Middlewares::ClaimsRule, name: 'github-revalidate') do |context, decision|
  next decision.skip! unless context.refresh?
  next decision.skip!("provider not in scope") unless context.refresh_info && context.refresh_info[:provider] == 'github'

  fresh = gh_exchange.call(context.refresh_info[:refresh_token])
  next decision.deny!("upstream refused refresh") unless fresh

  decision.initialize_claims!(
    sub: context.refresh_info[:sub],
    name: context.refresh_info[:nickname],
    preferred_username: context.refresh_info[:nickname],
    email: context.refresh_info[:email],
  )
  decision.user_data[:provider] = 'github'
  decision.refresh_info = context.refresh_info.merge(
    refresh_token: fresh['refresh_token'] || context.refresh_info[:refresh_token],
    access_token: fresh['access_token'],
    access_token_expires_at: Time.now.to_i + fresh.fetch('expires_in', 0),
  )
  decision.continue!
end

# Both paths: provider check via context.provider (works on initial via
# auth[:provider], on refresh via session.user_data[:provider]). The upstream
# access_token is read from decision.refresh_info — whichever of the prior
# two rules wrote it.
use(Himari::Middlewares::ClaimsRule, name: 'github-oauth-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  # https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user
  # (not available in GitHub Apps = only available in OAuth apps)
  user_teams_resp = gh_api.get('user/teams', {per_page: 100}, {
    'Accept' => 'application/vnd.github+json',
    'Authorization' => "Bearer #{decision.refresh_info[:access_token]}",
  }).body

  teams_in_scope = %w(
    contoso/engineers
    contoso/admins
  )
  teams = user_teams_resp
    .map { |team| "#{team.fetch("organization").fetch("login")}/#{team.fetch("slug")}" }
    .select { |login_slug| teams_in_scope.include?(login_slug) }

  next decision.skip!("no teams in scope") if teams.empty?

  decision.claims[:groups] ||= []
  decision.claims[:groups].concat(teams)
  decision.claims[:groups].uniq!

  decision.continue!
end

# Select who can be authenticated through Himari
use(Himari::Middlewares::AuthenticationRule, name: 'allow-github-with-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  if context.claims[:groups] && !context.claims[:groups].empty?
    next decision.allow!
  end

  decision.skip!
end
use(Himari::Middlewares::AuthenticationRule, name: 'deny-someone') do |context, decision|
  if context.claims[:sub] == 'something-to-ban'
    context.deny!
  end

  decision.skip!
end

# Authorize client on behalf of a signed in user based on authz rule
use(Himari::Middlewares::AuthorizationRule, name: 'default') do |context, decision|
  decision.allowed_claims.push(:groups)

  available_for_everyone = %w(
    wiki
  )

  if available_for_everyone.include?(context.client.name)
    next decision.allow!
  end

  decision.skip!
end

run Himari::App
