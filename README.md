# Himari - OIDC IdP for Small Team

Himari is a Rack application acts as a OIDC IdP. Identities are all externally sourced through Omniauth. This app aims to provide a common IdP for small team, where not suitable to have a full-suite IdP.

For instance, this app should fit for a team like: a team with individual collaborators, a team with members from multiple organizations. This app should enable OIDC for such teams using existing their own identities, without forcing them to manage new credentials for small purpose.

If your team can use full-suite IdP such as Azure AD, Okta or Google Workspace, then this app should be not for you.

While this app does not aim to be a replacement, but you can consider this as a cheaper alternative against Dex (dexidp), by deploying this to AWS Lambda.

## Installation

Deploy as a Rack application:

```ruby
# Gemfile
source 'https://rubygems.org'
gem 'himari'
```

```ruby
# config.ru
```

## Usage

TODO: Write usage instructions here

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [rubygems.org]().

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/[USERNAME]/himari.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
