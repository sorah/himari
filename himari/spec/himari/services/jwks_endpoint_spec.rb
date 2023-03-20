require 'spec_helper'
require 'himari/services/jwks_endpoint'

RSpec.describe Himari::Services::JwksEndpoint do
  include Rack::Test::Methods

  let(:keys) do
    [
      double('key a', as_jwk: {kid: 'a'}),
      double('key b', as_jwk: {kid: 'b'}),
    ]
  end

  let(:signing_key_provider) { double('chain', collect: keys) }
  let(:app) { described_class.new(signing_key_provider: signing_key_provider) }

  context "with non-GET request" do
    it "returns 404" do
      post '/jwks'
      expect(last_response.status).to eq(404)
    end
  end

  context "with GET request" do
    it "returns jwks" do
      get '/jwks'
      expect(last_response).to be_ok
      expect(last_response.content_type).to eq('application/json; charset=utf-8')
      expect(JSON.parse(last_response.body, symbolize_names: true)).to eq(keys: [{kid: 'a'}, {kid: 'b'}])
    end
  end
end
