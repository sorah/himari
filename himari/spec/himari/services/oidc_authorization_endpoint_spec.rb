require 'spec_helper'
require 'digest/sha2'
require 'base64'
require 'addressable'
require 'himari/services/oidc_authorization_endpoint'
require 'himari/storages/memory'
require 'himari/authorization_code'

RSpec.describe Himari::Services::OidcAuthorizationEndpoint do
  include Rack::Test::Methods

  let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}) }
  let(:client) { double('client', id: 'clientid', redirect_uris: ['https://rp.invalid/cb']) }
  let(:storage) { Himari::Storages::Memory.new }

  let(:app) { described_class.new(authz: authz, client: client, storage: storage) }

  context "with invalid clientid combination" do
    it "returns 400" do
      get '/oidc/authorize?client_id=invalidclientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb'
      expect(last_response.status).to eq(400)
    end
  end

  context "with unsupported response type" do
    it "returns error in fragment" do
      get '/oidc/authorize?client_id=clientid&response_type=code+id_token&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb'
      expect(last_response.status).to eq(302)
      fragment = Addressable::URI.parse(last_response.headers['location']).fragment
      expect(fragment).to include('error=unsupported_response_type')
    end
  end

  context "with invalid pkce" do
    it "returns 400" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&code_challenge=invalid&code_challenge_method=invalid'
      expect(last_response.status).to eq(302)
      error = Addressable::URI.parse(last_response.headers['location']).query_values['error']
      expect(error).to eq('invalid_request')
    end
  end

  context "with valid request" do
    it "returns a grant code" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
      expect(last_response.status).to eq(302)
      query = Addressable::URI.parse(last_response.headers['location']).query_values
      expect(query['state']).to eq('x')
      expect(query['code']).to be_a(String)

      authz = storage.find_authorization(query['code'])
      expect(authz).to be_a(Himari::AuthorizationCode)
      expect(authz.redirect_uri).to eq('https://rp.invalid/cb')
      expect(authz.nonce).to eq('nn')
      expect(authz.openid).to eq(true)
      expect(authz.code_challenge).to be_nil
      expect(authz.code_challenge_method).to be_nil
    end
  end

  context "with valid request using PKCE" do
    let(:code_verifier) { 'kakunin' }
    let(:code_challenge) { Base64.urlsafe_encode64(Digest::SHA256.digest(code_verifier), padding: false) }

    it "returns a grant code" do
      get "/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&code_challenge=#{code_challenge}&code_challenge_method=S256"
      expect(last_response.status).to eq(302)
      query = Addressable::URI.parse(last_response.headers['location']).query_values
      expect(query['state']).to eq('x')
      expect(query['code']).to be_a(String)

      authz = storage.find_authorization(query['code'])
      expect(authz).to be_a(Himari::AuthorizationCode)
      expect(authz.redirect_uri).to eq('https://rp.invalid/cb')
      expect(authz.nonce).to eq('nn')
      expect(authz.openid).to eq(true)
      expect(authz.code_challenge).to eq(code_challenge)
      expect(authz.code_challenge_method).to eq('S256')
    end
  end

end
