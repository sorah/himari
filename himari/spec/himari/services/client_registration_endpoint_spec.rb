# frozen_string_literal: true

require 'spec_helper'
require 'rack/null_logger'
require 'himari/services/client_registration_endpoint'
require 'himari/storages/memory'

RSpec.describe Himari::Services::ClientRegistrationEndpoint do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }
  let(:logger) { Rack::NullLogger.new(nil) }
  let(:app) { described_class.new(storage: storage, logger: logger) }

  def register(body)
    post '/oidc/register', JSON.generate(body), {'CONTENT_TYPE' => 'application/json'}
  end

  context "registering a public client" do
    it "returns 201 without a client_secret and persists it" do
      register(redirect_uris: %w(https://rp.test.invalid/cb), token_endpoint_auth_method: 'none')
      expect(last_response.status).to eq(201)
      expect(last_response.content_type).to eq('application/json')

      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:client_id]).to be_a(String)
      expect(body).not_to have_key(:client_secret)
      expect(body[:token_endpoint_auth_method]).to eq('none')

      stored = storage.find_dynamic_client(body[:client_id])
      expect(stored).not_to be_nil
      expect(stored.confidential?).to eq(false)
    end
  end

  context "registering a confidential client" do
    it "returns 201 with a one-time client_secret" do
      register(redirect_uris: %w(https://rp.test.invalid/cb), token_endpoint_auth_method: 'client_secret_basic')
      expect(last_response.status).to eq(201)

      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:client_secret]).to be_a(String)
      expect(body[:client_secret_expires_at]).to be_a(Integer)

      stored = storage.find_dynamic_client(body[:client_id])
      expect(stored.to_client_registration.match_secret?(body[:client_secret])).to eq(true)
    end
  end

  context "with invalid redirect_uris" do
    it "returns 400 invalid_redirect_uri" do
      register(redirect_uris: [])
      expect(last_response.status).to eq(400)
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:error]).to eq('invalid_redirect_uri')
    end
  end

  context "with unsupported metadata" do
    it "returns 400 invalid_client_metadata" do
      register(redirect_uris: %w(https://rp.test.invalid/cb), grant_types: %w(client_credentials))
      expect(last_response.status).to eq(400)
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:error]).to eq('invalid_client_metadata')
    end
  end

  context "with a non-JSON content type" do
    it "returns 400" do
      post '/oidc/register', 'redirect_uris=x', {'CONTENT_TYPE' => 'application/x-www-form-urlencoded'}
      expect(last_response.status).to eq(400)
    end
  end

  context "with a GET request" do
    it "returns 405" do
      get '/oidc/register'
      expect(last_response.status).to eq(405)
    end
  end
end
