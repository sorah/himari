# config.ru
require 'himari'
require 'himari/aws'
require 'json'
require 'omniauth'
require 'omniauth-github'
require 'rack'
require 'rack/session/cookie'
require 'faraday'

use(Rack::Session::Cookie,
  path: '/',
  expire_after: 3600,
  secure: true,
  secret: ENV.fetch('SECRET_KEY_BASE'),
)

use OmniAuth::Builder do
  provider :github
end

use(Himari::Middlewares::Config,
  issuer: 'https://idp.example.net',
  providers: [
    { name: :github, button: 'Log in with GitHub' },
  ],
  storage: Himari::Storages::Filesystem.new('/var/lib/himari/data'),
)

# Signing key
use(Himari::Middlewares::SigningKey,
  id: 'key1', # kid
  pkey: OpenSSL::PKey::RSA.new(File.read('...'), ''),
)

# Add clients as many as you need
use(Himari::Middlewares::Client,
  name: 'awsalb', # friendly name (this can be referenced from policies)
  id: '...',
  secret_hash: '...', # Digest::SHA384.hexdigest of actual secret
  redirect_uris: %w(https://app.example.net/oauth2/idpresponse),
)

use(Himari::Middlewares::ClaimsRule, name: 'github-initialize') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  decision.initialize_claims!(
    sub: "github_#{context.auth[:uid]}",
    name: context.auth[:info][:nickname],
    preferred_username: context.auth[:info][:nickname],
    email: context.auth[:info][:email],
  )
  decision.user_data[:provider] = 'github'

  decision.continue!
end
gh_faraday = Faraday.new(url: 'https://api.github.com') do |b|
  b.response :json
  b.response :raise_error
end
use(Himari::Middlewares::ClaimsRule, name: 'github-oauth-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  # https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user
  # (not available in GitHub Apps = only available in OAuth apps)
  user_teams_resp = gh_faraday.get('user/teams', {per_page: 100}, { 'Accept' => 'application/vnd.github+json', 'Authorization' => "Bearer #{context.auth[:credentials][:token]}" }).body

  teams_in_scope = %w(
    contoso/engineers
    contoso/admins
  )
  teams = user_teams_resp
    .map { |team| "#{team.fetch('organization').fetch('login')}/#{team.fetch('slug')}" }
    .select { |login_slug| teams_in_scope.include?(login_slug) }

  next decision.skip!("no teams in scope") if teams.empty?

  # claims
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

