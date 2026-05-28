# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

### Testing
- **Run all tests**: `cd himari && bundle exec rspec` (or in himari-aws/, omniauth-himari/)
- **Run specific test**: `cd himari && bundle exec rspec spec/path/to/spec.rb`
- **Run tests with coverage**: Tests automatically generate coverage reports with SimpleCov

### Development
- **Install dependencies**: `bundle install` (run at repository root)
- **Generate test signing keys**: `ruby dev/setup.rb`
- **Start development server**: Configure `dev/config.ru` then run `rackup dev/config.ru`
- **Build gem**: `cd himari && bundle exec rake build` (repeat for each subproject)
- **Release gem**: `cd himari && bundle exec rake release` (uses version prefix like `himari/0.5.0`)

### Docker (for AWS Lambda)
- **Build Lambda image**: `docker build -f himari-aws/lambda/Dockerfile .`
- **Test Lambda image locally**: See himari-aws/lambda/terraform/ for configuration

## Architecture Overview

Himari is a monorepo containing three Ruby gems:

1. **himari** - Core OIDC IdP implementation using Sinatra and Rack middleware
2. **himari-aws** - AWS integration (Lambda, DynamoDB, Secrets Manager)
3. **omniauth-himari** - Omniauth strategy for using Himari as an identity provider

### Core Architecture Patterns

**Middleware-based Configuration**: All configuration is injected via Rack middleware:
- `Himari::Middlewares::Config` - Main configuration
- `Himari::Middlewares::SigningKey` - JWT signing keys
- `Himari::Middlewares::Client` - Client registrations
- `Himari::Middlewares::*Rule` - Authentication/authorization rules

**Provider Chain Pattern**: Dynamic lookup for clients, keys, and rules:
- Providers are stored in arrays in Rack env (e.g., `env['himari.signing_keys']`)
- `ProviderChain` handles lookups with hint-based matching

**Rule Processing System**: Sequential rule evaluation with decision tracking:
- Rules process context and evolve decisions (allow/deny/continue/skip)
- `RuleProcessor` maintains logs and handles final decisions
- Three rule types: AuthenticationRule, AuthorizationRule, ClaimsRule

**Storage Abstraction**: Pluggable storage backends via strategy pattern:
- Base interface in `Himari::Storages::Base`
- Implementations: Memory, Filesystem, DynamoDB
- Handles sessions, authorization codes, and access tokens

### Key Service Classes

- `UpstreamAuthentication` - Processes OAuth callbacks from external providers
- `DownstreamAuthorization` - Handles client authorization requests
- `OidcAuthorizationEndpoint` - OIDC authorization endpoint logic
- `OidcTokenEndpoint` - Token exchange and validation
- `TokenString` - Token generation with HMAC verification

### OIDC Endpoints

- `GET /.well-known/openid-configuration` - Discovery metadata
- `GET /oidc/authorize` - Authorization endpoint
- `POST /public/oidc/token` - Token endpoint
- `GET /public/oidc/userinfo` - UserInfo endpoint
- `GET /public/jwks` - Public key set

### Development Notes

- All models use Struct with custom behavior methods
- Tokens include HMAC for verification (see `TokenString` module)
- Session data stored with configurable lifetimes
- PKCE support for public clients
- Templates customizable via `custom_templates` config

## Ruby Style Guide

Follow these Ruby conventions when working in this codebase:

### General Conventions
- Explicit requires at top of file
- Use keyword arguments for methods with multiple parameters
- Prefer `attr_reader` over instance variable access
- Omit hash or keyword argument value when it is identical to key: `{foo:}` instead of `{foo: foo}`

### Method Definitions
- Use `def self.method_name` for class methods
- Short single-line methods when appropriate
- Use guard clauses for early returns

### Error Handling
- Rescue specific errors (e.g., `Aws::DynamoDB::Errors::ResourceNotFoundException`)
- Raise with descriptive messages

### AWS SDK Usage
- Lazy initialize AWS clients as instance variables
- Pass logger to AWS clients
- Use symbolized keys for AWS responses

### Data Handling
- Use `fetch` for required hash keys
- Use `Hash#fetch` or `Array#fetch` when the key/index is expected to exist
- Consistent hash syntax with colons
- Use Struct or Data classes instead of raw Hashes

### Logging
- Use structured logging with JSON when appropriate
- Log important operations (locks, state changes)