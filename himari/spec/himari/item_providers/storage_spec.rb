# frozen_string_literal: true

require 'spec_helper'
require 'himari/item_providers/storage'
require 'himari/storages/memory'
require 'himari/dynamic_client_registration'

RSpec.describe Himari::ItemProviders::Storage do
  subject(:provider) { described_class.new(storage: storage) }

  let(:storage) { Himari::Storages::Memory.new }
  let(:client) { Himari::DynamicClientRegistration.register(metadata: {redirect_uris: %w(https://rp.test.invalid/cb), token_endpoint_auth_method: 'none'}) }

  before { storage.put_dynamic_client(client) }

  it "returns the client (as a ClientRegistration) for a matching id hint" do
    collected = provider.collect(id: client.id)
    expect(collected.map(&:id)).to eq([client.id])
    expect(collected.first).to be_a(Himari::ClientRegistration)
    expect(collected.first.skip_consent).to eq(false)
  end

  context "with skip_consent enabled" do
    subject(:provider) { described_class.new(storage: storage, skip_consent: true) }

    it "applies skip_consent to resolved clients" do
      expect(provider.collect(id: client.id).first.skip_consent).to eq(true)
    end
  end

  it "returns nothing without an id hint" do
    expect(provider.collect).to eq([])
  end

  it "returns nothing for an unknown id" do
    expect(provider.collect(id: 'unknown')).to eq([])
  end

  it "filters out expired registrations" do
    expired = Himari::DynamicClientRegistration.register(metadata: {redirect_uris: %w(https://rp.test.invalid/cb)}, now: Time.at(1))
    storage.put_dynamic_client(expired)
    expect(provider.collect(id: expired.id)).to eq([])
  end
end
