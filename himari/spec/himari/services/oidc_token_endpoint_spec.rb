# frozen_string_literal: true

require 'spec_helper'
require 'digest/sha2'
require 'base64'
require 'addressable'
require 'rack/null_logger'
require 'himari/services/oidc_token_endpoint'
require 'himari/storages/memory'
require 'himari/authorization_code'
require 'himari/id_token'
require 'himari/access_token'
require 'himari/refresh_token'
require 'himari/session_data'
require 'himari/lifetime_value'
require 'himari/rule'
require 'himari/item_providers/static'
require 'himari/middlewares/claims_rule'
require 'himari/middlewares/authentication_rule'
require 'himari/middlewares/authorization_rule'

RSpec.describe Himari::Services::OidcTokenEndpoint do
  include Rack::Test::Methods

  let(:lifetime_value) { Himari::LifetimeValue.new(id_token: 3600, access_token: 3600) }
  let(:scope_openid) { false }
  let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: scope_openid, lifetime: lifetime_value) }

  let(:require_pkce) { false }

  let(:confidential) { true }
  let(:client) do
    double('client', id: 'clientid', redirect_uris: ['https://rp.invalid/cb'], preferred_key_group: 'kagi', as_log: {client_as_log: 1}, require_pkce: require_pkce, confidential?: confidential).tap do |x|
      allow(x).to receive(:match_secret?).with('secret').and_return(true)
    end
  end
  let(:client_provider) do
    double('client_provider').tap do |x|
      allow(x).to receive(:find).with(id: 'clientid').and_return(client)
    end
  end

  let(:pkey) { OpenSSL::PKey::RSA.new(Himari::Testing::TEST_RSA_KEY_PEM, '') }
  let(:signing_key) { Himari::SigningKey.new(id: 'kid', pkey: pkey, inactive: false, group: 'kagi') }
  let(:signing_key_provider) do
    double('signing_key_provider').tap do |x|
      allow(x).to receive(:find).with(group: 'kagi', active: true).and_return(signing_key)
    end
  end

  let(:storage) { Himari::Storages::Memory.new }
  let(:logger) { Rack::NullLogger.new(nil) }

  let(:app) { described_class.new(client_provider: client_provider, signing_key_provider: signing_key_provider, storage: storage, issuer: 'https://test.invalid', logger: logger) }

  before do
    storage.put_authorization(authz)

    basic_authorize 'clientid', 'secret'
  end

  context "with unknown clientid" do
    before do
      allow(client_provider).to receive(:find).with(id: 'unknown').and_return(nil)
      basic_authorize 'unknown', 'sec'
    end

    it "returns 401" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(401)
    end
  end

  context "with invalid client secret" do
    before do
      allow(client).to receive(:match_secret?).with('sec').and_return(false)
      basic_authorize 'clientid', 'sec'
    end

    it "returns 401" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(401)
    end
  end

  context "with invalid grant type" do
    it "returns 400" do
      post '/oidc/token', 'grant_type' => 'password', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(400)
    end
  end

  context "with mismatch redirect uri" do
    it "returns 400" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/mismatch-cb'
      expect(last_response.status).to eq(400)
    end
  end

  context "with expired grant" do
    it "returns 400" do
      allow(Time).to receive(:now).and_return(authz.expiry + 1)
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(400)
    end
  end

  context "with invalid grant" do
    it "returns 400" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => 'invalid', 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(400)
    end
  end

  context "using PKCE" do
    let(:code_verifier) { 'kakunin' }
    let(:code_challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false) }
    let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: true, code_challenge: code_challenge, code_challenge_method: 'S256', lifetime: lifetime_value) }

    context "without verifier" do
      it "returns 400" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
        expect(last_response.status).to eq(400)
      end
    end

    context "with invalid verifier" do
      it "returns 400" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb', 'code_verifier' => 'invalid'
        expect(last_response.status).to eq(400)
      end
    end

    context "with valid verifier" do
      it "returns tokens" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb', 'code_verifier' => code_verifier
        expect(last_response.status).to eq(200)
        expect(last_response.content_type).to match(%r{^application/json})
      end
    end

    context "with valid verifier and when enforced" do
      let(:require_pkce) { true }
      it "returns tokens" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb', 'code_verifier' => code_verifier
        expect(last_response.status).to eq(200)
        expect(last_response.content_type).to match(%r{^application/json})
      end
    end
  end

  context "with grant issued to a different client" do
    let(:authz) { Himari::AuthorizationCode.make(client_id: 'otherclient', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: scope_openid, lifetime: lifetime_value) }

    it "returns 400" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(400)
    end
  end

  context "with a public client (token_endpoint_auth_method=none)" do
    let(:confidential) { false }
    let(:require_pkce) { true }
    let(:code_verifier) { 'kakunin' }
    let(:code_challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false) }
    let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: false, code_challenge: code_challenge, code_challenge_method: 'S256', lifetime: lifetime_value) }

    before { allow(client_provider).to receive(:find).with(id: 'clientid').and_return(client) }

    it "issues tokens with PKCE and no client secret" do
      post '/oidc/token', {'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb', 'code_verifier' => code_verifier, 'client_id' => 'clientid'}, {}
      expect(last_response.status).to eq(200)
    end

    it "rejects when PKCE verifier is missing" do
      post '/oidc/token', {'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb', 'client_id' => 'clientid'}, {}
      expect(last_response.status).to eq(400)
    end
  end

  context "with valid request" do
    it "returns tokens" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(200)
      expect(last_response.content_type).to match(%r{^application/json})
      body = JSON.parse(last_response.body, symbolize_names: true)

      expect(body[:token_type]).to eq('Bearer')
      expect(body[:expires_in]).to be_a(Integer)
      expect(body[:id_token]).to be_nil
      expect(body[:refresh_token]).to be_nil
      at = body[:access_token]
      expect(at).to be_a(String)
      parse = Himari::AccessToken.parse(at)
      token = storage.find_token(parse.handle)
      expect(token).not_to be_nil
      expect(token.verify_secret!(parse.secret)).to eq(true)
      expect(token.claims).to eq(sub: 'chihiro')

      expect(storage.find_authorization(authz.code)).to be_nil
    end

    context "with offline_access scope but lifetime.refresh_token unset" do
      let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: scope_openid, offline_access: true, session_handle: 'sess1', lifetime: lifetime_value) }

      it "does not issue refresh_token" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
        expect(last_response.status).to eq(200)
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body[:refresh_token]).to be_nil
      end
    end

    context "with offline_access scope and lifetime.refresh_token set" do
      let(:lifetime_value) { Himari::LifetimeValue.new(id_token: 3600, access_token: 3600, refresh_token: 7200) }
      let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: scope_openid, offline_access: true, session_handle: 'sess1', lifetime: lifetime_value) }

      it "issues a refresh_token persisted in storage" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
        expect(last_response.status).to eq(200)
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body[:refresh_token]).to be_a(String)

        parsed = Himari::RefreshToken.parse(body[:refresh_token])
        stored = storage.find_refresh_token(parsed.handle)
        expect(stored).not_to be_nil
        expect(stored.verify_secret!(parsed.secret)).to eq(true)
        expect(stored.session_handle).to eq('sess1')
        expect(stored.client_id).to eq('clientid')
      end

      it "skips refresh_token when session_handle missing" do
        authz2 = Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: scope_openid, offline_access: true, session_handle: nil, lifetime: lifetime_value)
        storage.put_authorization(authz2)
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz2.code, 'redirect_uri' => 'https://rp.invalid/cb'
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body[:refresh_token]).to be_nil
      end
    end

    context "when PKCE enforced" do
      let(:require_pkce) { true }
      it "returns 400" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
        expect(last_response.status).to eq(400)
      end
    end

    context "using openid scope" do
      let(:scope_openid) { true }

      before do
        expect(Himari::IdToken).to receive(:new) do |claims:, client_id:, nonce:, signing_key:, issuer:, access_token:, lifetime:|
          expect(claims).to eq(authz.claims)
          expect(client_id).to eq('clientid')
          expect(nonce).to eq(authz.nonce)
          expect(issuer).to eq('https://test.invalid')
          expect(signing_key).to eq(signing_key)
          expect(lifetime).to eq(3600)
          double('jwt', to_jwt: access_token)
        end
      end

      it "returns tokens" do
        post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
        expect(last_response.status).to eq(200)
        expect(last_response.content_type).to match(%r{^application/json})
        body = JSON.parse(last_response.body, symbolize_names: true)

        expect(body[:token_type]).to eq('Bearer')
        expect(body[:expires_in]).to be_a(Integer)
        expect(body[:access_token]).to be_a(String)
        expect(body[:id_token]).to be_a(String)

        # mock returns access_token as an id_token
        expect(body[:id_token]).to eq(body[:access_token])

        expect(storage.find_authorization(authz.code)).to be_nil
      end
    end
  end

  describe "grant_type=refresh_token" do
    let(:session) do
      Himari::SessionData.make(claims: {sub: 'chihiro'}, user_data: {provider: 'test'}).tap do |s|
        # opt the session into refresh by setting refresh_info (rule-supplied snapshot)
        s.instance_variable_set(:@refresh_info, {sub: 'chihiro', provider: 'test', token: 'upstream'})
      end
    end

    let(:refresh) do
      Himari::RefreshToken.make(
        client_id: 'clientid',
        claims: {sub: 'chihiro'},
        session_handle: session.handle,
        openid: false,
        lifetime: 7200,
      )
    end

    let(:claims_rule) do
      Himari::Rule.new(name: 'claims', block: proc { |c, d|
        d.initialize_claims!(sub: c.refresh_info[:sub])
        d.user_data[:provider] = c.refresh_info[:provider]
        d.continue!
      })
    end

    let(:authn_rule) do
      Himari::Rule.new(name: 'authn', block: proc { |c, d|
        d.refresh_info = c.refresh_info if c.refresh_info
        d.allow!
      })
    end

    let(:authz_rule) do
      Himari::Rule.new(name: 'authz', block: proc { |_c, d|
        d.lifetime = Himari::LifetimeValue.new(access_token: 3600, id_token: 3600, refresh_token: 7200)
        d.allow!
      })
    end

    before do
      storage.put_session(session)
      storage.put_refresh_token(refresh)
    end

    def post_refresh(token, env_extra = {})
      env = {
        Himari::Middlewares::ClaimsRule::RACK_KEY => [Himari::ItemProviders::Static.new([claims_rule])],
        Himari::Middlewares::AuthenticationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authn_rule])],
        Himari::Middlewares::AuthorizationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authz_rule])],
      }.merge(env_extra)
      post '/oidc/token', {'grant_type' => 'refresh_token', 'refresh_token' => token}, env
    end

    it "issues a new access token and rotates the refresh token in place" do
      post_refresh(refresh.format.to_s)
      expect(last_response.status).to eq(200)
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:access_token]).to be_a(String)
      expect(body[:refresh_token]).to be_a(String)
      expect(body[:refresh_token]).not_to eq(refresh.format.to_s)

      # rotation is in place: the handle is stable, the secret and version change.
      new_parsed = Himari::RefreshToken.parse(body[:refresh_token])
      expect(new_parsed.handle).to eq(refresh.handle)
      expect(new_parsed.secret).not_to eq(refresh.secret)

      stored = storage.find_refresh_token(refresh.handle)
      expect(stored).not_to be_nil
      expect(stored.version).to eq(refresh.version + 1)
      expect(stored.session_handle).to eq(session.handle)
      # the rotated token verifies against the new secret...
      expect(stored.verify_secret!(new_parsed.secret)).to eq(true)
      # ...and still against the just-presented (now previous) secret.
      expect(storage.find_refresh_token(refresh.handle).verify_secret!(refresh.secret)).to eq(true)
    end

    it "tolerates a lost rotation response: the previous secret refreshes once more" do
      post_refresh(refresh.format.to_s)
      expect(last_response.status).to eq(200)
      first = JSON.parse(last_response.body, symbolize_names: true)

      # Simulate the client never receiving `first`: it retries with the original secret,
      # which is now the previous secret on the rotated (same-handle) token.
      post_refresh(refresh.format.to_s)
      expect(last_response.status).to eq(200)
      retried = JSON.parse(last_response.body, symbolize_names: true)
      expect(retried[:refresh_token]).not_to eq(first[:refresh_token])

      stored = storage.find_refresh_token(refresh.handle)
      expect(stored.version).to eq(refresh.version + 2)
    end

    it "rejects and revokes a secret that is two generations old" do
      post_refresh(refresh.format.to_s) # version+1, prev = original secret
      first = JSON.parse(last_response.body, symbolize_names: true)
      post_refresh(first[:refresh_token]) # version+2, prev = first secret; original retired

      # The original secret is now neither current nor previous: a leak signal.
      post_refresh(refresh.format.to_s)
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    it "rejects the loser without revoking on a version conflict" do
      # A concurrent refresh that already rotated this handle bumps the version, so the
      # compare-and-swap on the version we read conflicts. Reject without revoking, so the
      # winner's rotated token (same handle) survives.
      allow(storage).to receive(:put_refresh_token).and_raise(Himari::Storages::Base::Conflict)

      post_refresh(refresh.format.to_s)
      expect(last_response.status).to eq(400)

      # not revoked: the token is still present (find is real; only put was stubbed).
      expect(storage.find_refresh_token(refresh.handle)).not_to be_nil
    end

    it "rejects unknown refresh_token" do
      post_refresh('hmrt.unknown.secret')
      expect(last_response.status).to eq(400)
    end

    it "rejects refresh_token with bad secret" do
      garbage = Himari::TokenString::Format.new(header: 'hmrt', handle: refresh.handle, secret: 'wrong').to_s
      post_refresh(garbage)
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    it "rejects when session has no refresh_info" do
      session.instance_variable_set(:@refresh_info, nil)
      storage.put_session(session, overwrite: true)
      post_refresh(refresh.format.to_s)
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    it "rejects and revokes when authn rule denies" do
      deny_rule = Himari::Rule.new(name: 'authn', block: proc { |_c, d| d.deny! })
      post '/oidc/token', {'grant_type' => 'refresh_token', 'refresh_token' => refresh.format.to_s}, {
        Himari::Middlewares::ClaimsRule::RACK_KEY => [Himari::ItemProviders::Static.new([claims_rule])],
        Himari::Middlewares::AuthenticationRule::RACK_KEY => [Himari::ItemProviders::Static.new([deny_rule])],
        Himari::Middlewares::AuthorizationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authz_rule])],
      }
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    it "rejects and revokes when claims rule explicitly denies" do
      deny_claims_rule = Himari::Rule.new(name: 'claims', block: proc { |_c, d| d.deny!("upstream refused refresh") })
      post '/oidc/token', {'grant_type' => 'refresh_token', 'refresh_token' => refresh.format.to_s}, {
        Himari::Middlewares::ClaimsRule::RACK_KEY => [Himari::ItemProviders::Static.new([deny_claims_rule])],
        Himari::Middlewares::AuthenticationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authn_rule])],
        Himari::Middlewares::AuthorizationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authz_rule])],
      }
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    it "rejects and revokes when authz rule denies" do
      deny_rule = Himari::Rule.new(name: 'authz', block: proc { |_c, d| d.deny! })
      post '/oidc/token', {'grant_type' => 'refresh_token', 'refresh_token' => refresh.format.to_s}, {
        Himari::Middlewares::ClaimsRule::RACK_KEY => [Himari::ItemProviders::Static.new([claims_rule])],
        Himari::Middlewares::AuthenticationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authn_rule])],
        Himari::Middlewares::AuthorizationRule::RACK_KEY => [Himari::ItemProviders::Static.new([deny_rule])],
      }
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    it "rejects and revokes refresh_token for different client" do
      other_refresh = Himari::RefreshToken.make(client_id: 'otherclient', claims: {sub: 'chihiro'}, session_handle: session.handle, openid: false, lifetime: 7200)
      storage.put_refresh_token(other_refresh)
      post_refresh(other_refresh.format.to_s)
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(other_refresh.handle)).to be_nil
    end

    it "rejects and revokes when authz rule no longer configures a refresh_token lifetime" do
      no_refresh_rule = Himari::Rule.new(name: 'authz', block: proc { |_c, d|
        d.lifetime = Himari::LifetimeValue.new(access_token: 3600, id_token: 3600, refresh_token: nil)
        d.allow!
      })
      post '/oidc/token', {'grant_type' => 'refresh_token', 'refresh_token' => refresh.format.to_s}, {
        Himari::Middlewares::ClaimsRule::RACK_KEY => [Himari::ItemProviders::Static.new([claims_rule])],
        Himari::Middlewares::AuthenticationRule::RACK_KEY => [Himari::ItemProviders::Static.new([authn_rule])],
        Himari::Middlewares::AuthorizationRule::RACK_KEY => [Himari::ItemProviders::Static.new([no_refresh_rule])],
      }
      expect(last_response.status).to eq(400)
      expect(storage.find_refresh_token(refresh.handle)).to be_nil
    end

    context "with openid refresh" do
      let(:refresh) do
        Himari::RefreshToken.make(
          client_id: 'clientid',
          claims: {sub: 'chihiro'},
          session_handle: session.handle,
          openid: true,
          lifetime: 7200,
        )
      end

      it "issues new id_token (without nonce)" do
        expect(Himari::IdToken).to receive(:new) do |claims:, client_id:, nonce:, signing_key:, issuer:, **|
          expect(nonce).to be_nil
          expect(claims).to eq(sub: 'chihiro')
          expect(client_id).to eq('clientid')
          expect(issuer).to eq('https://test.invalid')
          expect(signing_key).to eq(signing_key)
          double('jwt', to_jwt: 'id-token-string')
        end

        post_refresh(refresh.format.to_s)
        expect(last_response.status).to eq(200)
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body[:id_token]).to eq('id-token-string')
      end
    end
  end
end
