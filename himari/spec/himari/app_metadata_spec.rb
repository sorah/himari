# frozen_string_literal: true

require 'spec_helper'
require 'rack/builder'
require 'himari'
require 'himari/middlewares/config'
require 'himari/middlewares/metadata_clients'
require 'himari/storages/memory'

RSpec.describe 'App authorization server metadata routes' do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }
  let(:metadata_clients_enabled) { false }

  let(:app) do
    s = storage
    enabled = metadata_clients_enabled
    Rack::Builder.new do
      use Himari::Middlewares::Config, issuer: 'https://test.invalid', storage: s, log_level: Logger::FATAL
      use Himari::Middlewares::MetadataClients if enabled
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

  describe 'client_id_metadata_document_supported advertisement' do
    context 'when MetadataClients is absent' do
      it 'omits the flag from both documents' do
        %w(/.well-known/openid-configuration /.well-known/oauth-authorization-server).each do |path|
          get path
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body).not_to have_key(:client_id_metadata_document_supported)
        end
      end
    end

    context 'when MetadataClients is enabled' do
      let(:metadata_clients_enabled) { true }

      it 'advertises the flag in both documents' do
        %w(/.well-known/openid-configuration /.well-known/oauth-authorization-server).each do |path|
          get path
          body = JSON.parse(last_response.body, symbolize_names: true)
          expect(body[:client_id_metadata_document_supported]).to eq(true)
        end
      end
    end
  end
end
