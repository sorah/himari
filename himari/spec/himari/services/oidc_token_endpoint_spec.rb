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
require 'himari/lifetime_value'

RSpec.describe Himari::Services::OidcTokenEndpoint do
  include Rack::Test::Methods

  let(:lifetime_value) { Himari::LifetimeValue.new(id_token: 3600, access_token: 3600) }
  let(:scope_openid) { false }
  let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, redirect_uri: 'https://rp.invalid/cb', openid: scope_openid, lifetime: lifetime_value) }

  let(:require_pkce) { false }

  let(:client) do
    double('client', id: 'clientid', redirect_uris: ['https://rp.invalid/cb'], preferred_key_group: 'kagi', as_log: {client_as_log: 1}, require_pkce: require_pkce).tap do |x|
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

  context "with valid request" do
    it "returns tokens" do
      post '/oidc/token', 'grant_type' => 'authorization_code', 'code' => authz.code, 'redirect_uri' => 'https://rp.invalid/cb'
      expect(last_response.status).to eq(200)
      expect(last_response.content_type).to match(%r{^application/json})
      body = JSON.parse(last_response.body, symbolize_names: true)

      expect(body[:token_type]).to eq('Bearer')
      expect(body[:expires_in]).to be_a(Integer)
      expect(body[:id_token]).to be_nil
      at = body[:access_token]
      expect(at).to be_a(String)
      parse = Himari::AccessToken.parse(at)
      token = storage.find_token(parse.handle)
      expect(token).not_to be_nil
      expect(token.verify_secret!(parse.secret)).to eq(true)
      expect(token.claims).to eq(sub: 'chihiro')

      expect(storage.find_authorization(authz.code)).to be_nil
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
        expect(Himari::IdToken).to receive(:from_authz) do |authz_, signing_key:, access_token:, issuer:|
          expect(authz_.code).to eq(authz.code)
          expect(issuer).to eq('https://test.invalid')
          expect(signing_key).to eq(signing_key)
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
end
