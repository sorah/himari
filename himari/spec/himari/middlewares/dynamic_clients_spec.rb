# frozen_string_literal: true

require 'spec_helper'
require 'himari/middlewares/dynamic_clients'
require 'himari/middlewares/config'
require 'himari/middlewares/client'
require 'himari/storages/memory'

RSpec.describe Himari::Middlewares::DynamicClients do
  let(:storage) { Himari::Storages::Memory.new }
  let(:config) { double('config', storage: storage) }
  let(:downstream) { ->(_env) { [200, {}, ['ok']] } }
  subject(:middleware) { described_class.new(downstream) }

  def env_with_config
    {Himari::Middlewares::Config::RACK_KEY => config}
  end

  it "sets the enable flag and appends a storage provider to the client chain" do
    env = env_with_config
    middleware.call(env)

    expect(env[described_class::RACK_KEY]).to be_a(described_class::Options)
    expect(env[Himari::Middlewares::Client::RACK_KEY].last).to be_a(Himari::ItemProviders::Storage)
  end

  it "defaults registration_lifetime to the model default" do
    env = env_with_config
    middleware.call(env)
    expect(env[described_class::RACK_KEY].registration_lifetime).to eq(Himari::DynamicClientRegistration::REGISTRATION_LIFETIME)
  end

  it "honors a configured registration_lifetime" do
    env = env_with_config
    described_class.new(downstream, registration_lifetime: 3600).call(env)
    expect(env[described_class::RACK_KEY].registration_lifetime).to eq(3600)
  end

  it "preserves existing static client providers" do
    env = env_with_config.merge(Himari::Middlewares::Client::RACK_KEY => [:static_provider])
    middleware.call(env)

    expect(env[Himari::Middlewares::Client::RACK_KEY].first).to eq(:static_provider)
    expect(env[Himari::Middlewares::Client::RACK_KEY].size).to eq(2)
  end

  it "raises when Config middleware did not run first" do
    expect { middleware.call({}) }.to raise_error(/after Himari::Middlewares::Config/)
  end
end
