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
  let(:app) { described_class.new(signing_key_provider: signing_key_provider, issuer: 'https://test.invalid') }

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
