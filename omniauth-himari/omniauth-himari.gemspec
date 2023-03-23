# frozen_string_literal: true

require_relative "lib/omniauth-himari/version"

Gem::Specification.new do |spec|
  spec.name = "omniauth-himari"
  spec.version = Omniauth::Himari::VERSION
  spec.authors = ["Sorah Fukumori"]
  spec.email = ["her@sorah.jp"]

  spec.summary = "OmniAuth strategy for Himari"
  spec.description = "OmniAuth strategy to act as OIDC RP and use [Himari](https://github.com/sorah/himari) for OP."
  spec.homepage = "https://github.com/sorah/himari"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sorah/himari"
  #spec.metadata["changelog_uri"] = "TODO: Put your gem's CHANGELOG.md URL here."

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  if ENV['HIMARI_LAMBDA_IMAGE']
    spec.files = Dir.chdir(__dir__) { Dir["./**/*"] }.reject { |f|  (File.expand_path(f) == __FILE__) }
  else
    spec.files = Dir.chdir(__dir__) do
      `git ls-files -z`.split("\x0").reject do |f|
        (f == __FILE__) || f.match(%r{\A(?:(?:bin|test|spec|features)/|\.(?:git|travis|circleci)|appveyor)})
      end
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency 'omniauth'
  spec.add_dependency 'omniauth-oauth2'
  spec.add_dependency 'oauth2'
  spec.add_dependency 'faraday'

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
