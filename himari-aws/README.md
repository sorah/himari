# himari-aws: AWS related plugins for Himari

- DynamoDB storage backend
- Secrets Manager automatic rotation Lambda function for signing keys
- Secrets Manager signing key provider
- Lambda container image to host Himari itself (TODO)

## Installation

```ruby
gem 'himari'
gem 'himari-aws'
gem 'nokogiri'
```

### IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:DeleteItem",
        "dynamodb:Query",
        "dynamodb:UpdateItem"
      ],
      "Resource": "arn:aws:dynamodb:[REGION]:[ACCOUNTID]:table/himari_*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:DescribeSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:UpdateSecretVersionStage"
      ],
      "Resource": "arn:aws:secretsmanager:[REGION]:[ACCOUNTID]:secret:himari_*"
    }
  ]
}
```

## Usage

### Setup secrets manager secret

1. Deploy [./lib/himari/aws/secretsmanager_signing_key_rotation_handler.rb]() as a Lambda function. This file works standalone.

   - TODO: container image

2. Grant secrets manager a `lambda:InvokeFunction` to the function.
3. Create a secrets manager secret and set up rotation.

You can tag a secret with `HimariKey` key and the following value to customize key types:

- RSA 2048-bit: `{"kty": "rsa", "len": 2048}`
- RSA 4096-bit: `{"kty": "rsa", "len": 4096}`
- EC P-256: `{"kty": "ec", "len": 256}`

### config.ru

```ruby
# config.ru
require 'himari'
require 'himari/aws'
require 'json'
require 'omniauth'
require 'open-uri'
require 'rack/session'

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
  storage: Himari::Aws::DynamodbStorage.new(table_name: 'himari'),
)

# Signing key from Secrets Manager. For rotation deployment, read 
use(Himari::Aws::SecretsmanagerSigningKeyProvider, 
  secret_id: 'arn:aws:secretsmanager:ap-northeast-1:...:secret:himari-xxx',
  group: nil,
  kid_prefix: 'asm1',
)

# Add clients as many as you need
use(Himari::Middlewares::Client,
  name: 'awsalb',
  id: '...',
  secret_hash: '...', # sha384 hexdigest of secret
  # secret: '...' # or in cleartext
  redirect_uris: %w(https://app.example.net/oauth2/idpresponse),
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

use(Himari::Middlewares::AuthenticationRule, name: 'always-allow') do |context, decision|
  next decision.skip!("provider not in scope") unless context.provider == 'developer'
  decision.allow!
end

use(Himari::Middleware::AuthorizationRule, name: 'always-allow') do |context, decision|
  decision.allow! 
end

run Himari::App
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sorah/himari.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
