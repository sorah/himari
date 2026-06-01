# frozen_string_literal: true

require 'spec_helper'
require 'rack/builder'
require 'rack/session/cookie'
require 'addressable'
require 'himari'
require 'himari/middlewares/config'
require 'himari/middlewares/client'
require 'himari/storages/memory'

RSpec.describe 'App /oidc/authorize prompt propagation through login' do
  include Rack::Test::Methods

  let(:storage) { Himari::Storages::Memory.new }

  let(:app) do
    s = storage
    Rack::Builder.new do
      use Rack::Session::Cookie, secret: 'a' * 64
      use Himari::Middlewares::Config, issuer: 'https://test.invalid', storage: s, providers: [{name: :developer}], log_level: Logger::FATAL
      use Himari::Middlewares::Client, id: 'cid', name: 'client1', redirect_uris: %w(https://rp.invalid/cb), confidential: false
      run Himari::App
    end
  end

  # The login page renders a per-provider form whose action carries a back_to URL pointing at the
  # original authorize request; pull the prompt out of that nested URL.
  def back_to_prompt
    action = last_response.body[%r{action="(/auth/developer[^"]*)"}, 1]
    back_to = Addressable::URI.parse(action).query_values.fetch('back_to')
    Addressable::URI.parse(back_to).query_values['prompt']
  end

  def authorize(prompt)
    get "/oidc/authorize?client_id=cid&response_type=code&scope=openid&state=x&redirect_uri=https%3A%2F%2Frp.invalid%2Fcb&prompt=#{prompt}"
    expect(last_response.status).to eq(200)
  end

  it "preserves prompt=consent so it still applies after login" do
    authorize('consent')
    expect(back_to_prompt).to eq('consent')
  end

  it "drops prompt=login to avoid re-triggering the login screen in a loop" do
    authorize('login')
    expect(back_to_prompt).to be_nil
  end

  it "drops prompt=select_account too" do
    authorize('select_account')
    expect(back_to_prompt).to be_nil
  end

  it "keeps only consent when login and consent are combined" do
    authorize('login+consent')
    expect(back_to_prompt).to eq('consent')
  end
end
