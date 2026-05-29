# frozen_string_literal: true

require 'spec_helper'
require 'himari/storages/memory'
require 'himari/refresh_token'
require 'himari/dynamic_client_registration'

RSpec.describe Himari::Storages::Memory do
  subject(:storage) { described_class.new }

  describe "dynamic clients" do
    let(:client) { Himari::DynamicClientRegistration.register(metadata: {redirect_uris: %w(https://rp.test.invalid/cb), token_endpoint_auth_method: 'client_secret_basic'}) }

    it "round-trips put/find/delete by id" do
      storage.put_dynamic_client(client)
      found = storage.find_dynamic_client(client.id)
      expect(found.id).to eq(client.id)
      expect(found.to_client_registration.match_secret?(client.secret)).to eq(true)

      storage.delete_dynamic_client(client)
      expect(storage.find_dynamic_client(client.id)).to be_nil
    end

    it "returns nil for an unknown id" do
      expect(storage.find_dynamic_client('nope')).to be_nil
    end

    it "returns nil (without reading storage) for an id with disallowed characters" do
      expect(storage.find_dynamic_client('../authz/code')).to be_nil
    end
  end

  let(:token) do
    Himari::RefreshToken.make(client_id: 'cli', claims: {sub: 'c'}, session_handle: 'sess', openid: false, lifetime: 7200)
  end

  describe "#put_refresh_token with if_version" do
    before { storage.put_refresh_token(token) }

    it "writes when the stored version matches" do
      token.verify_secret!(token.secret)
      rotated = token.rotate(claims: {sub: 'c'}, openid: false)
      storage.put_refresh_token(rotated, if_version: token.version)
      expect(storage.find_refresh_token(token.handle).version).to eq(rotated.version)
    end

    it "raises Conflict when the stored version does not match" do
      token.verify_secret!(token.secret)
      rotated = token.rotate(claims: {sub: 'c'}, openid: false)
      expect { storage.put_refresh_token(rotated, if_version: token.version + 1) }.to raise_error(Himari::Storages::Base::Conflict)
    end

    it "raises Conflict when the record is absent" do
      orphan = Himari::RefreshToken.make(client_id: 'cli', claims: {sub: 'c'}, session_handle: 'sess', openid: false, lifetime: 7200)
      expect { storage.put_refresh_token(orphan, if_version: 1) }.to raise_error(Himari::Storages::Base::Conflict)
    end
  end
end
