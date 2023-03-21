# frozen_string_literal: true

require_relative "lib/himari/version"

Gem::Specification.new do |spec|
  spec.name = "himari"
  spec.version = Himari::VERSION
  spec.authors = ["Sorah Fukumori"]
  spec.email = ["her@sorah.jp"]

  spec.summary = "Small OIDC IdP for small teams - Omniauth to OIDC"
  spec.homepage = "https://github.com/sorah/himari"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 2.7.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/sorah/himari"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  if ENV['HIMARI_LAMBDA_IMAGE']
    spec.files = Dir.chdir(__dir__) { Dir["./**/*"] }.reject { |f|  (File.expand_path(f) == __FILE__) }
  else
    spec.files = Dir.chdir(__dir__) do
      `git ls-files -z`.split("\x0").reject do |f|
        (File.expand_path(f) == __FILE__) || f.start_with?(*%w[bin/ test/ spec/ features/ .git .circleci appveyor])
      end
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "sinatra", '>= 3.0'
  spec.add_dependency 'rack-protection'
  spec.add_dependency "omniauth", ">= 2.0"

  spec.add_dependency 'addressable'

  spec.add_dependency "rack-oauth2"
  spec.add_dependency "openid_connect"

  # Uncomment to register a new dependency of your gem
  # spec.add_dependency "example-gem", "~> 1.0"

  # For more information and examples about making a new gem, check out our
  # guide at: https://bundler.io/guides/creating_gem.html
end
