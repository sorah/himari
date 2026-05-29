# frozen_string_literal: true

require 'spec_helper'
require 'rack/builder'
require 'himari'
require 'himari/middlewares/config'
require 'himari/middlewares/dynamic_clients'
require 'himari/storages/memory'

RSpec.describe 'App dynamic client registration routes' do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }
  let(:dynamic_clients_enabled) { true }

  let(:app) do
    s = storage
    enabled = dynamic_clients_enabled
    Rack::Builder.new do
      use Himari::Middlewares::Config, issuer: 'https://test.invalid', storage: s, log_level: Logger::FATAL
      use Himari::Middlewares::DynamicClients if enabled
      run Himari::App
    end
  end

  context "when DynamicClients middleware is enabled" do
    it "registers a client and advertises the endpoint" do
      post '/public/oidc/register', JSON.generate(redirect_uris: %w(https://rp.test.invalid/cb), token_endpoint_auth_method: 'none'), {'CONTENT_TYPE' => 'application/json'}
      expect(last_response.status).to eq(201)

      get '/.well-known/openid-configuration'
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:registration_endpoint]).to eq('https://test.invalid/public/oidc/register')
    end

    it "answers 405 for a non-POST request to the registration endpoint" do
      get '/public/oidc/register'
      expect(last_response.status).to eq(405)
      expect(JSON.parse(last_response.body, symbolize_names: true)[:error]).to eq('invalid_request')
    end
  end

  context "when DynamicClients middleware is absent" do
    let(:dynamic_clients_enabled) { false }

    it "returns 404 for the registration endpoint and omits the advertisement" do
      post '/public/oidc/register', JSON.generate(redirect_uris: %w(https://rp.test.invalid/cb)), {'CONTENT_TYPE' => 'application/json'}
      expect(last_response.status).to eq(404)

      get '/.well-known/openid-configuration'
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body).not_to have_key(:registration_endpoint)
    end
  end
end
