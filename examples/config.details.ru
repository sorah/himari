# config.ru
require 'himari'
require 'himari/aws'
require 'json'
require 'omniauth'
require 'open-uri'
require 'rack/session/cookie'

use(Rack::Session::Cookie,
  path: '/',
  expire_after: 3600,
  secure: true,
  secret: ENV.fetch('SECRET_KEY_BASE'),
)

use OmniAuth::Builder do
  provider :developer, fields: %i(login), uid_field: :login
end

use(Himari::Middlewares::Config,
  issuer: 'https://idp.example.net',
  providers: [
    { name: :github, button: 'Log in with GitHub' },
  ],
  storage: Himari::Aws::DynamoDbStorage.new(table_name: 'test'),
  # log_level: Logger::DEBUG,
)

# Signing key
use(Himari::Middlewares::SigningKey,
  id: 'kid', # kid
  pkey: OpenSSL::PKey::RSA.new(File.read('...'), ''),
  group: 'group', # for preferred_key_group in a Client definition
  inactive: false, # key will not be used for signing when set to true
)

# Add clients as many as you need
use(Himari::Middlewares::Client,
  name: 'awsalb', # friendly name (this can be referenced from policies)
  id: '...',
  secret: '...',
  redirect_uris: %w(https://app.example.net/oauth2/idpresponse),
  preferred_key_group: 'group', # specify this is a client prefers specific signing key group
)

## CLAIM RULES: Generate claims on provider authentication
#
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
use(Himari::Middlewares::ClaimsRule, name: 'details') do |context, decision|
  # auth hash and authhash[:provider]
  context.auth
  context.provider

  # Rack::Request
  context.request

  # claims
  decision.initialize_claims!
  decision.claims

  # databag (data not exposed to clients)
  decision.user_data

  # Rule must always call one of the followings
  next decision.continue! # save claims and continue
  next decision.skip! # skip (and discard claims)

  # TODO: ideas;
  #decision.inherit_claims!
  #next decision.authenticate_with!(:second_factor) # redirect to provider for second factor authentication

  nil # return value is not used at all
end

## AUTHN RULE
# Select who can be authenticated through Himari
use(Himari::Middlewares::AuthenticationRule, name: 'allow-github-with-teams') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  if context.claims[:groups] && !context.claims[:group].empty?
    next decision.allow!
  end
  
  decision.skip!
end
use(Himari::Middlewares::AuthenticationRule, name: 'details') do |context, decision|
  # provider
  context.provider

  # claims
  context.claims
  context.user_data

  # Rack::Request
  context.request

  # Rule must always call one of the followings
  next decision.deny! # explicit deny, stop processing
  next decision.allow! # allow, continues processing to find explicit deny
  next decision.skip! # make no decision, continues processing

  nil # return value is not used at all
end

## AUTHZ RULE
# Authorization policies during OIDC request process from clients
use(Himari::Middlewares::AuthorizationRule, name: 'default') do |context, decision|
  available_for_everyone = %w(
    wiki
  )

  decision.allowed_claims.push(:groups)

  next decision.allow! if available_for_everyone.include?(context.client.name)
  decision.skip!
end

use(Himari::Middlewares::AuthorizationRule, name: 'details') do |context, decision|
  # claims
  context.claims
  context.user_data

  # Rack::Request
  context.request

  # client
  context.client.name

  # custom claims per authorization
  decision.claims[:something] =  'these claims merged for specific authorization request'
  # allowed claims (Set). Names not included in allowed_claims will not appear in an outbound ID token.
  decision.allowed_claims.push(:something)

  # Rule must always call one of the followings
  next decision.deny! # explicit deny, stop processing
  next decision.allow! # allow, continues processing
  next decision.continue! # make no decision (preserves modified claims), continues processing
  next decision.skip! # make no decision (discards modified claims), continues processing

  # deny can have human facing error
  next decision.deny!("internal log message", user_facing_message: 'error message for user') # explicit deny, stop processing

  # authorization deny can suggest user to reauthenticate
  next decision.deny!("reauthenticate", suggest: :reauthenticate)
end

run Himari::App

