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
    footer: <<~EOH,
      <p>
        <small>
          Powered by <a href="https://github.com/sorah/himari">sorah/himari</a>
        </small>
      </p>
    EOH
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
  decision.user_data[:auth_time] = Time.now.to_i
  decision.continue!
end
use(Himari::Middlewares::ClaimsRule, name: 'developer-custom') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'developer'
  decision.claims[:something1] = 'custom1'
  decision.continue!
end


use(Himari::Middlewares::AuthenticationRule, name: 'allow-dev') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'developer'

  #decision.deny!('test', user_facing_message: 'human test')
  decision.allow!
end

#### AUTHZ RULE

use(Himari::Middlewares::AuthorizationRule, name: 'old-auth') do |context, decision|
  if context.claims[:name] == 'reauth'
    next decision.deny!('because you are reauth', suggest: :reauthenticate, user_facing_message: 'you are reauth...')
  end
  if !context.user_data[:auth_time] || Time.now.to_i > (context.user_data[:auth_time] + 60)
    next decision.deny!('too old auth_time', suggest: :reauthenticate)
  end
  decision.skip!
end

use(Himari::Middlewares::AuthorizationRule, name: 'default') do |context, decision|
  decision.claims[:something2] =  'custom2'
  decision.allowed_claims.push(:something1)
  decision.allowed_claims.push(:something2)
  decision.allow!
end

run Himari::App

