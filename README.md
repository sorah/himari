# Himari - OIDC IdP for Small Team

Himari is a Rack application acts as a OIDC IdP. Identities are all externally sourced through Omniauth. This app aims to provide a common IdP for small team, where not suitable to have a full-suite IdP.

For instance, this app should fit for a team like: a team with individual collaborators, a team with members from multiple organizations. This app should enable OIDC for such teams using existing their own identities, without forcing them to manage new credentials for small purpose.

If your team can use full-suite IdP such as Azure AD, Okta or Google Workspace, then this app may not be for you.

While this app does not aim to be a replacement, but you can consider this as a cheaper alternative against Dex (dexidp), by deploying this to AWS Lambda.

## Setup

<i>See [./lambda-aws/lambda/terraform/](./lambda-aws/lambda/terraform/) for quick deployment on Lambda using Terraform modules.</i>

Deploy as a Rack application:

```ruby
# Gemfile
source 'https://rubygems.org'
gem 'himari'
gem 'himari-aws' # for AWS Secrets Manager integration and DynamoDB storage backend

gem 'nokogiri' # for himari-aws
gem 'rack-session'
```

Write policy and configuration in config.ru. Then run as a Rack application:

```ruby
# config.ru
require 'himari'
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
  provider :github
end

use(Himari::Middlewares::Config,
  issuer: 'https://idp.example.net',
  providers: [
    { name: :github, button: 'Log in with GitHub' },
  ],
  storage: Himari::Storages::Filesystem.new('/var/lib/himari/data'),
)

# add signing key. multiple keys can be added for rotation
use(Himari::Middlewares::SigningKey,
  kid: 'key1',
  pkey: OpenSSL::PKey::RSA.new(File.read('key.pem'), ''),
)

# Add clients as many as you need
use(Himari::Middlewares::Client,
  name: 'awsalb',
  id: '...',
  secret_hash: '...', # sha384 hexdigest of secret
  # secret: '...' # or in cleartext
  redirect_uris: %w(https://app.example.net/oauth2/idpresponse),
)

# Generate claims from omniauth authentication result
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

# Select who can be authenticated through Himari. Authn rules run during omniauth callback
use(Himari::Middlewares::AuthenticationRule, name: 'allow-github-known-members') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'github'

  known_logins = %w(chihiro maki hare kotama himari)
  if known_logins.include?(context.claims[:preferred_username])
    next decision.allow!
  end

  decision.skip!
end

# Authorization policies during OIDC request process from clients. Authz rules run during oidc authorization
use(Himari::Middlewares::AuthorizationRule, name: 'default') do |context, decision|
  clients_available_for_everyone = %w(wiki)

  # You can add custom_claim per client
  decision.claims[:custom_claim1] = 'foo'
  decision.allowed_claims.push(:custom_claim)

  if clients_available_for_everyone.include?(context.client.name)
    next decision.allow! 
  end
  decision.skip!
end
# we can have many rules
use(Himari::Middlewares::AuthorizationRule, name: 'ban-something') do |context, decision|
  if context.request.ip == '192.0.2.9'
    next decision.deny!("explicit deny for some banned ip")
  end

  decision.skip!
end

# Run!
run Himari::App
```

## Plugins

- [./himari-aws]() for AWS Lambda, DynamoDB and Secrets Manager integration

## Examples

- [./examples/config.details.ru](): Rule API details
- [./examples/config.github.ru](): GitHub Team list API example
- [./himari-aws]() for AWS Lambda, DynamoDB and Secrets Manager integration

## Usage

Himari acts as an OIDC OpenID Provider. OIDC discovery metadata served at `/.well-known/openid-configuration`.

- Authorize Endpoint: `/oidc/authorize`
- Token Endpoint: `/public/oidc/token`
- Userinfo Endpoint: `/public/oidc/userinfo`
- JWK Set Endpoint: `/public/jwks`

## Caveats

- Consent/Authorize screen is not implemented. All authorization requests will be immediately approved on behalf of a logged in user, as long as AuthorizationRule permits.
- Recognizes `openid` scope only.
- Implements Authorization Code Flow (`response_type=code`) only. Public clients should use the same flow with PKCE.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org]().

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sorah/himari.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
