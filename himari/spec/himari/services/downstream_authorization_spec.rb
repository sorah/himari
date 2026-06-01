# frozen_string_literal: true

require 'spec_helper'

require 'himari/services/downstream_authorization'
require 'himari/rule'
require 'himari/item_providers/static'
require 'himari/middlewares/authorization_rule'

RSpec.describe Himari::Services::DownstreamAuthorization do
  let(:rack_request) { double('rack request', params: {'scope' => 'openid profile email'}) }
  let(:session_data) { double('session data', claims: {claims: 1}, user_data: {user_data: 1}) }
  let(:client) { double('client registration', filter_scopes: %w(openid profile)) }

  let(:authz_rules) do
    [
      # Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
    ]
  end

  let(:requested_scopes) { %w(openid profile email) }
  subject(:service) { described_class.new(session: session_data, client: client, request: rack_request, requested_scopes: requested_scopes, authz_rules: authz_rules) }
  subject(:result) { service.perform }

  describe "nominal case" do
    let(:authz_rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |c, d|
          c.client.ok # mark
          expect(c.claims[:claims]).to eq(1)
          expect(c.user_data[:user_data]).to eq(1)
          expect(c.request).to eq(rack_request)
          expect(c.scopes).to eq(%w(openid profile))

          expect(d.claims[:claims]).to eq(1)
          d.allowed_claims.push(:claims, :new_claims)
          d.claims[:claims] = 2
          d.claims[:new_claims] = 2
          d.lifetime = 12345
          d.allow!
        }),
      ]
    end

    it "returns an authorization" do
      expect(client).to receive(:ok)
      expect(result.client).to eq(client)
      expect(result.claims).to eq(claims: 2, new_claims: 2)
      expect(result.scopes).to eq(%w(openid profile))
      expect(result.lifetime.access_token).to eq(12345)
      expect(result.lifetime.id_token).to eq(12345)
      expect(result.authz_result.allowed).to eq(true)
    end
  end

  describe "mint_jwt_access_token" do
    it "defaults to false and carries a rule's opt-in onto the Result" do
      expect(described_class.new(session: session_data, client: client, request: rack_request, requested_scopes: requested_scopes, authz_rules: [
        Himari::Rule.new(name: 'allow', block: proc { |_c, d| d.allow! }),
      ]).perform.mint_jwt_access_token).to eq(false)

      expect(described_class.new(session: session_data, client: client, request: rack_request, requested_scopes: requested_scopes, authz_rules: [
        Himari::Rule.new(name: 'allow', block: proc { |_c, d|
          d.mint_jwt_access_token = true
          d.allow!
        }),
      ]).perform.mint_jwt_access_token).to eq(true)
    end
  end

  describe "scope filtering" do
    it "filters the requested scopes through the client's allow-list and exposes them to rules" do
      expect(client).to receive(:filter_scopes).with(%w(openid profile email)).and_return(%w(openid profile))
      seen = nil
      rules = [Himari::Rule.new(name: 'allow', block: proc { |c, d|
        seen = c.scopes
        d.allow!
      })]
      result = described_class.new(session: session_data, client: client, request: rack_request, requested_scopes: %w(openid profile email), authz_rules: rules).perform
      expect(seen).to eq(%w(openid profile))
      expect(result.scopes).to eq(%w(openid profile))
    end

    it "never reads the request object to derive scopes (it is only a rule escape hatch)" do
      expect(rack_request).not_to receive(:params)
      allow(client).to receive(:filter_scopes).and_return([])
      described_class.new(session: session_data, client: client, request: rack_request, requested_scopes: %w(profile), authz_rules: [Himari::Rule.new(name: 'allow', block: proc { |_c, d| d.allow! })]).perform
    end
  end

  describe ".from_request" do
    let(:allow_rule) { Himari::Rule.new(name: 'allow', block: proc { |_c, d| d.allow! }) }
    let(:env) { {Himari::Middlewares::AuthorizationRule::RACK_KEY => [Himari::ItemProviders::Static.new([allow_rule])], 'rack.logger' => nil} }
    let(:request) { double('request', env: env) }

    it "wires the authz rules from the request env and forwards the caller's scopes" do
      expect(request).not_to receive(:params)
      expect(client).to receive(:filter_scopes).with(%w(openid profile)).and_return(%w(openid profile))
      seen = nil
      env[Himari::Middlewares::AuthorizationRule::RACK_KEY] = [Himari::ItemProviders::Static.new([
        Himari::Rule.new(name: 'allow', block: proc { |c, d|
          seen = c.scopes
          d.allow!
        }),
      ])]
      described_class.from_request(session: session_data, client: client, request: request, requested_scopes: %w(openid profile)).perform
      expect(seen).to eq(%w(openid profile))
    end
  end

  describe "authz denial case" do
    let(:authz_rules) do
      [
        Himari::Rule.new(name: 'deny', block: proc { |_c, d| d.deny! }),
      ]
    end

    it "raises ForbiddenError" do
      expect { result }.to raise_error(Himari::Services::DownstreamAuthorization::ForbiddenError)
    end
  end

  describe "no claims case" do
    let(:authz_rules) do
      []
    end

    it "raises ForbiddenError" do
      expect { result }.to raise_error(Himari::Services::DownstreamAuthorization::ForbiddenError)
    end
  end
end
