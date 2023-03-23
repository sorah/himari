# OmniAuth strategy for Himari

OmniAuth strategy to act as OIDC RP and use [Himari](https://github.com/sorah/himari) for OP.

## Installation

```ruby
# Gemfile
gem 'omniauth-himari'
```

## Usage

### Setup

```ruby
use OmniAuth::Builder do
  provider :himari, {
    site: 'https://himari.example.invalid',
    client_id: '...',
    client_secret: '...',

    # verify_options: { ... } # JWT.decode verify options override
    # verify_at_hash: true, # Verify at_hash returned in ID token

    # use_userinfo: false # force use of userinfo endpoint for raw_info
    # jwks_url: '...' # JWKs url to override (default=/public/jwks)

    # user_agent: '...' # user-agent to send (default=OmniAuthHimari/X.Y.Z)

    ## omniauth-oauth2 common strategy options
    # client_options: { ... },
    # pkce: true,
  }
end
```

### Auth Hash

```json
{
  "provider": "himari",
  "uid": "id_claim.sub",
  "info": {
    "name": "name || sub",
    "nickname": "preferred_username",
    "email": "email",
    "first_name": "given_name",
    "last_name": "family_name",
    "image": "picture"
  },
  "credentials": {
    "token": "access_token",
    "expires_at": 42,
    "expires": true,
    "id_token": "id_token"
  },
  "extra": {
    "userinfo_used": false,
    "id_token": {
      "claims": {
        "sub": "sub",
        "name": "name",
        "preferred_username": "preferred_username",
        "iss": "https://himari.example.invalid",
        "aud": "...",
        "iat": 1679595201,
        "nbf": 1679595201,
        "exp": 1679598801,
        "at_hash": "..."
      },
      "header": {
        "typ": "JWT",
        "alg": "RS256",
        "kid": "..."
      }
    },
    "raw_info": {
      "sub": "sub",
      "name": "name",
      "preferred_username": "preferred_username",
      "iss": "https://himari.example.invalid",
      "aud": "...",
      "iat": 1679595201,
      "nbf": 1679595201,
      "exp": 1679598801,
      "at_hash": "..."
    }
  }
}
```


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/sorah/himari.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
