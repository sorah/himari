# frozen_string_literal: true

require 'spec_helper'
require 'digest/sha2'
require 'base64'
require 'addressable'
require 'rack/null_logger'
require 'himari/services/oidc_authorization_endpoint'
require 'himari/client_registration'
require 'himari/storages/memory'
require 'himari/authorization_code'

RSpec.describe Himari::Services::OidcAuthorizationEndpoint do
  include Rack::Test::Methods

  let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}) }
  let(:require_pkce) { false }
  let(:skip_consent) { true }
  let(:consent) { nil }
  let(:redirect_uris) { ['https://rp.invalid/cb'] }
  let(:client) { Himari::ClientRegistration.new(id: 'clientid', redirect_uris:, confidential: false, require_pkce:, skip_consent:) }
  let(:storage) { Himari::Storages::Memory.new }
  let(:logger) { Rack::NullLogger.new(nil) }

  let(:app) { described_class.new(authz: authz, client: client, storage: storage, consent: consent, logger: logger) }

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

  context "with prompt=login" do
    it "raises ReauthenticationRequired" do
      expect do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&prompt=login'
      end.to raise_error(Himari::Services::OidcAuthorizationEndpoint::ReauthenticationRequired)
    end
  end

  context "with prompt=none+login" do
    it "raises ReauthenticationRequired" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&prompt=none+login'
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

    context "when pkce enforced" do
      let(:require_pkce) { true }
      it "returns invalid_request" do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
        expect(last_response.status).to eq(302)
        error = Addressable::URI.parse(last_response.headers['location']).query_values['error']
        expect(error).to eq('invalid_request')
      end
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

    context "with pkce enforced" do
      let(:require_pkce) { true }

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

  context "with prompt=none" do
    it "returns a grant code" do
      get "/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&prompt=none"
      expect(last_response.status).to eq(302)
      query = Addressable::URI.parse(last_response.headers['location']).query_values
      expect(query['state']).to eq('x')
      expect(query['code']).to be_a(String)
    end
  end

  context "with scope=offline_access" do
    let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, session_handle: 'sess1') }

    it "marks offline_access=true and carries session_handle onto the AuthorizationCode" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid+offline_access&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
      expect(last_response.status).to eq(302)
      query = Addressable::URI.parse(last_response.headers['location']).query_values

      stored = storage.find_authorization(query['code'])
      expect(stored.offline_access).to eq(true)
      expect(stored.openid).to eq(true)
      expect(stored.session_handle).to eq('sess1')
    end
  end

  context "without scope=offline_access" do
    let(:authz) { Himari::AuthorizationCode.make(client_id: 'clientid', claims: {sub: 'chihiro'}, session_handle: 'sess1') }

    it "marks offline_access=false" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
      stored = storage.find_authorization(Addressable::URI.parse(last_response.headers['location']).query_values['code'])
      expect(stored.offline_access).to eq(false)
    end
  end

  context "when consent is required (skip_consent=false)" do
    let(:skip_consent) { false }

    context "with no consent decision yet" do
      it "raises ConsentRequired carrying the client and recognised scopes only" do
        expect do
          get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid+profile&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
        end.to raise_error(Himari::Services::OidcAuthorizationEndpoint::ConsentRequired) do |e|
          expect(e.client).to eq(client)
          expect(e.scopes).to contain_exactly('openid')
        end
      end

      context "when the client declares the requested scope" do
        let(:client) { Himari::ClientRegistration.new(id: 'clientid', redirect_uris:, confidential: false, require_pkce:, skip_consent:, scopes: %w(profile)) }

        it "keeps the declared scope alongside the implicit ones" do
          expect do
            get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid+profile&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
          end.to raise_error(Himari::Services::OidcAuthorizationEndpoint::ConsentRequired) do |e|
            expect(e.scopes).to contain_exactly('openid', 'profile')
          end
        end
      end
    end

    context "when consent is approved" do
      let(:consent) { :approve }

      it "returns a grant code" do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
        expect(last_response.status).to eq(302)
        query = Addressable::URI.parse(last_response.headers['location']).query_values
        expect(query['code']).to be_a(String)
        expect(storage.find_authorization(query['code'])).to be_a(Himari::AuthorizationCode)
      end
    end

    context "when consent is denied" do
      let(:consent) { :deny }

      it "redirects with error=access_denied" do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn'
        expect(last_response.status).to eq(302)
        query = Addressable::URI.parse(last_response.headers['location']).query_values
        expect(query['error']).to eq('access_denied')
        expect(query['state']).to eq('x')
      end
    end

    context "with prompt=none" do
      it "redirects with error=consent_required instead of prompting" do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&prompt=none'
        expect(last_response.status).to eq(302)
        query = Addressable::URI.parse(last_response.headers['location']).query_values
        expect(query['error']).to eq('consent_required')
      end
    end
  end

  context "when skip_consent=true but prompt=consent forces the page" do
    it "raises ConsentRequired" do
      expect do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&prompt=consent'
      end.to raise_error(Himari::Services::OidcAuthorizationEndpoint::ConsentRequired)
    end

    context "when forced consent is approved" do
      let(:consent) { :approve }

      it "returns a grant code" do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&nonce=nn&prompt=consent'
        expect(last_response.status).to eq(302)
        query = Addressable::URI.parse(last_response.headers['location']).query_values
        expect(query['code']).to be_a(String)
      end
    end
  end

  context "with a mismatched redirect_uri" do
    it "returns invalid_request without redirecting" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Fattacker.invalid%2Fcb&nonce=nn'
      expect(last_response.status).to eq(400)
    end
  end

  context "with a loopback redirect_uri using an ephemeral port" do
    let(:redirect_uris) { ['http://127.0.0.1/cb'] }

    it "accepts any port and stores the actual redirect_uri" do
      get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcb&nonce=nn'
      expect(last_response.status).to eq(302)
      query = Addressable::URI.parse(last_response.headers['location']).query_values
      stored = storage.find_authorization(query['code'])
      expect(stored.redirect_uri).to eq('http://127.0.0.1:54321/cb')
    end

    context "when ignore_localhost_redirect_uri_port is disabled" do
      let(:client) { Himari::ClientRegistration.new(id: 'clientid', redirect_uris:, confidential: false, require_pkce:, skip_consent:, ignore_localhost_redirect_uri_port: false) }

      it "rejects a differing port" do
        get '/oidc/authorize?client_id=clientid&response_type=code&scope=openid&state=x&redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcb&nonce=nn'
        expect(last_response.status).to eq(400)
      end
    end
  end
end
