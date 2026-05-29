# frozen_string_literal: true

require 'spec_helper'
require 'himari/middlewares/metadata_clients'
require 'himari/middlewares/config'
require 'himari/middlewares/client'
require 'himari/storages/memory'

RSpec.describe Himari::Middlewares::MetadataClients do
  let(:storage) { Himari::Storages::Memory.new }
  let(:config) { double('config', storage: storage) }
  let(:downstream) { ->(_env) { [200, {}, ['ok']] } }
  subject(:middleware) { described_class.new(downstream) }

  def env_with_config
    {Himari::Middlewares::Config::RACK_KEY => config}
  end

  it "sets the enable flag and appends a metadata provider to the client chain" do
    env = env_with_config
    middleware.call(env)

    expect(env[described_class::RACK_KEY]).to be_a(described_class::Options)
    expect(env[Himari::Middlewares::Client::RACK_KEY].last).to be_a(Himari::ItemProviders::OauthClientMetadata)
  end

  it "reuses the same provider instance across requests (session/cache retained)" do
    env1 = env_with_config
    env2 = env_with_config
    middleware.call(env1)
    middleware.call(env2)

    expect(env1[Himari::Middlewares::Client::RACK_KEY].last).to equal(env2[Himari::Middlewares::Client::RACK_KEY].last)
  end

  it "defaults to requiring PKCE and accepting any compliant client_id" do
    env = env_with_config
    middleware.call(env)
    expect(env[described_class::RACK_KEY].require_pkce).to eq(true)
    expect(env[described_class::RACK_KEY].allowed_client_ids).to eq([])
  end

  it "honors configured options" do
    env = env_with_config
    described_class.new(downstream, require_pkce: false, allowed_client_ids: ['https://x.example/m'], max_response_size: 1024).call(env)
    opts = env[described_class::RACK_KEY]
    expect(opts.require_pkce).to eq(false)
    expect(opts.allowed_client_ids).to eq(['https://x.example/m'])
    expect(opts.max_response_size).to eq(1024)
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

  it "rejects an invalid ssrf option at build time" do
    expect { described_class.new(downstream, ssrf: :bogus) }.to raise_error(ArgumentError, /ssrf option/)
  end
end
