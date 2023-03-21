# config.ru
require 'himari'
require 'himari/aws'
require 'himari/storages/filesystem'
require 'json'
require 'omniauth'
require 'open-uri'
require 'rack/session/cookie'

use(Rack::Session::Cookie,
  key: 'op_session',
  path: '/',
  expire_after: 3600,
  #secure: true,
  secret: SecureRandom.hex(32),
)

use OmniAuth::Builder do
  provider :developer, fields: %i(login), uid_field: :login
end

use(Himari::Middlewares::Config,
  issuer: 'http://localhost:3000',
  providers: [
    { name: :developer, button: 'Log in with Dev' },
  ],
  # storage: Himari::Storages::Filesystem.new(File.join(__dir__, 'tmp', 'storage')),
  storage: Himari::Aws::DynamodbStorage.new(table_name: 'himari_dev'),
  log_level: Logger::DEBUG,
  release_fragment: "#{Process.pid}",
  custom_messages: {
    header: '<p>  header </p>',
  },
)

# Signing key
use(Himari::Aws::SecretsmanagerSigningKeyProvider, 
  secret_id: 'arn:aws:secretsmanager:ap-northeast-1:341857463381:secret:himari_dev-5EgiV8',
  group: nil,
  kid_prefix: 'sm_dev',
 )
if File.exist?(File.join(__dir__, 'tmp/rsa.pem'))
  use(Himari::Middlewares::SigningKey,
    id: 'rsa1',
    pkey: OpenSSL::PKey::RSA.new(File.read(File.join(__dir__, 'tmp/rsa.pem')), ''),
    group: nil,
    inactive: false,
  )
end
if File.exist?(File.join(__dir__, 'tmp/ec.pem'))
  use(Himari::Middlewares::SigningKey,
    id: 'ec1',
    pkey: OpenSSL::PKey::EC.new(File.read(File.join(__dir__, 'tmp/ec.pem')), ''),
    group: 'ec',
    inactive: false,
  )
end

# Add clients as many as you need
use(Himari::Middlewares::Client,
  name: 'client1', # friendly name (this can be referenced from policies)
  id: 'myclient1',
  secret: 'himitsudayo1',
  redirect_uris: %w(http://localhost:3001/auth/himari/callback),
  preferred_key_group: nil,
)

use(Himari::Middlewares::ClaimsRule, name: 'developer-initialize') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'developer'
  decision.initialize_claims!(
    sub: "dev_#{Digest::SHA256.hexdigest(context.auth[:uid])}",
    name: context.auth[:info][:login],
    preferred_username: context.auth[:info][:login],
  )
  decision.continue!
end
use(Himari::Middlewares::ClaimsRule, name: 'developer-custom') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'developer'
  decision.claims[:something1] = 'custom1'
  decision.continue!
end

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
use(Himari::Middlewares::ClaimsRule, name: 'github-oauth-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  # https://docs.github.com/en/rest/teams/teams?apiVersion=2022-11-28#list-teams-for-the-authenticated-user
  # (not available in GitHub Apps = only available in OAuth apps)
  user_teams_resp = JSON.parse(URI.open('https://api.github.com/user/teams?per_page=100', { 'Accept' => 'application/vnd.github+json', 'Authorization' => "Bearer #{context.auth[:credentials][:token]}" }, 'r', &:read))

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

use(Himari::Middlewares::AuthenticationRule, name: 'allow-dev') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'developer'

  #decision.deny!
  decision.allow!
end
use(Himari::Middlewares::AuthenticationRule, name: 'allow-github-with-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  if context.claims[:groups] && !context.claims[:group].empty?
    next decision.allow!
  end
  
  decision.skip!
end

# Authorization policies during OIDC request process from clients
use(Himari::Middlewares::AuthorizationRule, name: 'default') do |context, decision|
  decision.claims[:something2] =  'custom2'
  decision.allowed_claims.push(:something1)
  decision.allowed_claims.push(:something2)
  decision.allow!
end

run Himari::App

