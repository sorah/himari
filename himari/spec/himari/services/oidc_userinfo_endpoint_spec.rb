require 'spec_helper'
require 'himari/services/oidc_userinfo_endpoint'
require 'himari/storages/memory'
require 'himari/access_token'

RSpec.describe Himari::Services::OidcUserinfoEndpoint do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }

  let(:token) { Himari::AccessToken.make(client_id: 'clientid', claims: {sub: 'chihiro'}) }
  let(:bearer) { nil }
  let(:logger) { Rack::NullLogger.new(nil) }

  let(:app) { described_class.new(storage: storage, logger: logger) }

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
    let(:bearer) { "Bearer #{token.format.to_s}eyJ" }

    it "returns 401" do
      get '/oidc/userinfo'
      expect(last_response.status).to eq(401)
    end
  end

  context "with valid token" do
    let(:bearer) { "Bearer #{token.format.to_s}" }

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

end
