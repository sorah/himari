# frozen_string_literal: true

require 'spec_helper'
require 'himari/services/oidc_provider_metadata_endpoint'

RSpec.describe Himari::Services::OidcProviderMetadataEndpoint do
  include Rack::Test::Methods

  let(:keys) do
    [
      double('key a', alg: 'RS256'),
    ]
  end

  let(:signing_key_provider) { double('chain', collect: keys) }
  let(:registration_endpoint) { nil }
  let(:client_id_metadata_document_supported) { false }
  let(:scopes_supported) { [] }
  let(:claims_supported) { [] }
  let(:app) { described_class.new(signing_key_provider: signing_key_provider, issuer: 'https://test.invalid', registration_endpoint: registration_endpoint, client_id_metadata_document_supported: client_id_metadata_document_supported, scopes_supported: scopes_supported, claims_supported: claims_supported) }

  context "with non-GET request" do
    it "returns 404" do
      post '/.well-known/openid-configuration'
      expect(last_response.status).to eq(404)
    end
  end

  context "with GET request" do
    context "with 1 key" do
      it "returns metadata" do
        get '/.well-known/openid-configuration'
        expect(last_response).to be_ok
        expect(last_response.content_type).to eq('application/json; charset=utf-8')
        body = JSON.parse(last_response.body, symbolize_names: true)

        expect(body[:id_token_signing_alg_values_supported]).to eq(%w(RS256))
      end

      context "without dynamic client registration" do
        it "omits registration_endpoint" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body).not_to have_key(:registration_endpoint)
        end
      end

      context "with dynamic client registration" do
        let(:registration_endpoint) { 'https://test.invalid/public/oidc/register' }

        it "advertises registration_endpoint" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body[:registration_endpoint]).to eq('https://test.invalid/public/oidc/register')
        end
      end

      context "without metadata client registrations" do
        it "omits client_id_metadata_document_supported" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body).not_to have_key(:client_id_metadata_document_supported)
        end
      end

      context "with metadata client registrations" do
        let(:client_id_metadata_document_supported) { true }

        it "advertises client_id_metadata_document_supported" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body[:client_id_metadata_document_supported]).to eq(true)
        end
      end

      context "without additional scopes/claims" do
        it "advertises the default scopes and claims" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body[:scopes_supported]).to eq(%w(openid offline_access))
          expect(body[:claims_supported]).to eq(%w(sub iss iat nbf exp))
        end
      end

      context "with additional scopes/claims" do
        let(:scopes_supported) { %w(profile email) }
        let(:claims_supported) { %w(name email) }

        it "merges them with the defaults" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body[:scopes_supported]).to eq(%w(openid offline_access profile email))
          expect(body[:claims_supported]).to eq(%w(sub iss iat nbf exp name email))
        end
      end

      context "with additional scopes/claims overlapping the defaults" do
        let(:scopes_supported) { %w(openid profile) }
        let(:claims_supported) { %w(sub name) }

        it "de-duplicates while preserving order" do
          get '/.well-known/openid-configuration'
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body[:scopes_supported]).to eq(%w(openid offline_access profile))
          expect(body[:claims_supported]).to eq(%w(sub iss iat nbf exp name))
        end
      end
    end

    context "with 2 keys" do
      let(:keys) do
        [
          double('key a', alg: 'RS256'),
          double('key b', alg: 'ES256'),
        ]
      end

      it "returns metadata" do
        get '/.well-known/openid-configuration'
        expect(last_response).to be_ok
        expect(last_response.content_type).to eq('application/json; charset=utf-8')
        body = JSON.parse(last_response.body, symbolize_names: true)

        expect(body[:id_token_signing_alg_values_supported]).to eq(%w(ES256 RS256))
      end
    end
  end
end
