# frozen_string_literal: true

require 'spec_helper'
require 'rack/builder'
require 'himari'
require 'himari/middlewares/config'
require 'himari/storages/memory'

RSpec.describe 'App authorization server metadata routes' do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }

  let(:app) do
    s = storage
    Rack::Builder.new do
      use Himari::Middlewares::Config, issuer: 'https://test.invalid', storage: s, log_level: Logger::FATAL
      run Himari::App
    end
  end

  describe 'GET /.well-known/openid-configuration (OpenID Connect Discovery)' do
    it 'returns metadata' do
      get '/.well-known/openid-configuration'
      expect(last_response).to be_ok
      body = JSON.parse(last_response.body, symbolize_names: true)
      expect(body[:issuer]).to eq('https://test.invalid')
    end
  end

  describe 'GET /.well-known/oauth-authorization-server (RFC 8414)' do
    it 'returns metadata identical to OpenID Connect Discovery' do
      get '/.well-known/oauth-authorization-server'
      expect(last_response).to be_ok
      expect(last_response.content_type).to eq('application/json; charset=utf-8')
      oauth_body = last_response.body

      get '/.well-known/openid-configuration'
      expect(oauth_body).to eq(last_response.body)
    end
  end
end
