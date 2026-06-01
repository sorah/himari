# frozen_string_literal: true

require 'spec_helper'
require 'himari/services/oidc_userinfo_endpoint'
require 'himari/storages/memory'
require 'himari/access_token'
require 'himari/access_token_jwt'
require 'himari/signing_key'
require 'himari/provider_chain'
require 'himari/item_providers/static'

RSpec.describe Himari::Services::OidcUserinfoEndpoint do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }

  let(:pkey) { OpenSSL::PKey::RSA.new(Himari::Testing::TEST_RSA_KEY_PEM, '') }
  let(:signing_key) { Himari::SigningKey.new(id: 'kid', pkey: pkey, inactive: false, group: 'kagi') }
  let(:signing_key_provider) { Himari::ProviderChain.new([Himari::ItemProviders::Static.new([signing_key])]) }

  let(:token) { Himari::AccessToken.make(client_id: 'clientid', claims: {sub: 'chihiro'}) }
  let(:bearer) { nil }
  let(:logger) { Rack::NullLogger.new(nil) }

  let(:app) { described_class.new(storage: storage, signing_key_provider: signing_key_provider, logger: logger) }

  before do
    storage.put_token(token)

    header('Authorization', bearer) if bearer
  end

  context "without token" do
    let(:bearer) { nil }

    it "returns 401" do
      get '/oidc/userinfo'
      expect(last_response.status).to eq(401)
    end
  end

  context "with invalid token" do
    let(:bearer) { 'token invalid' }

    it "returns 401" do
      get '/oidc/userinfo'
      expect(last_response.status).to eq(401)
    end
  end

  context "with invalid bearer token" do
    let(:bearer) { 'Bearer invalid' }

    it "returns 401" do
      get '/oidc/userinfo'
      expect(last_response.status).to eq(401)
    end
  end

  context "with invalid bearer token2" do
    let(:bearer) { "Bearer #{token.format}eyJ" }

    it "returns 401" do
      get '/oidc/userinfo'
      expect(last_response.status).to eq(401)
    end
  end

  context "with valid token" do
    let(:bearer) { "Bearer #{token.format}" }

    it "returns metadata" do
      get '/oidc/userinfo'
      expect(last_response).to be_ok
      expect(last_response.content_type).to eq('application/json; charset=utf-8')
      body = JSON.parse(last_response.body, symbolize_names: true)

      expect(body).to eq(
        aud: 'clientid',
        sub: 'chihiro',
      )
    end
  end

  context "with a valid RFC 9068 JWT access token" do
    let(:jwt) do
      Himari::AccessTokenJwt.new(access: token, claims: token.claims, client_id: 'clientid', signing_key: signing_key, issuer: 'https://test.invalid').to_jwt
    end
    let(:bearer) { "Bearer #{jwt}" }

    it "verifies the signature, resolves hmat, and returns metadata" do
      get '/oidc/userinfo'
      expect(last_response).to be_ok
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body).to eq(aud: 'clientid', sub: 'chihiro')
    end
  end

  context "with a JWT access token signed by an unknown key" do
    let(:other_pkey) { OpenSSL::PKey::RSA.generate(2048) }
    let(:other_key) { Himari::SigningKey.new(id: 'kid', pkey: other_pkey, inactive: false, group: 'kagi') }
    let(:jwt) do
      Himari::AccessTokenJwt.new(access: token, claims: token.claims, client_id: 'clientid', signing_key: other_key, issuer: 'https://test.invalid').to_jwt
    end
    let(:bearer) { "Bearer #{jwt}" }

    it "returns 401" do
      get '/oidc/userinfo'
      expect(last_response.status).to eq(401)
    end
  end
end
