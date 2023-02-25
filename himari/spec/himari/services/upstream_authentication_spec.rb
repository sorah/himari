require 'spec_helper'

require 'himari/services/upstream_authentication'
require 'himari/rule'

RSpec.describe Himari::Services::UpstreamAuthentication do
  let(:rack_request) { double('rack request') }
  let(:auth_hash) { {provider: 'test', id: 'abcdef', name: 'himari'} }

  let(:claims_rules) do
    [
      # Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
    ]
  end

  let(:authn_rules) do
    [
      # Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
    ]
  end

  subject(:service) { described_class.new(auth: auth_hash, request: rack_request, claims_rules: claims_rules, authn_rules: authn_rules) }
  subject(:result) { service.perform }

  describe "nominal case" do

    let(:claims_rules) do
      [
        Himari::Rule.new(name: 'claims', block: proc { |c,d| d.initialize_claims!(sub: c.auth[:id], preferred_username: c.auth[:name]); d.user_data[:foo] = :bar; d.continue! }),
      ]
    end

    let(:authn_rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |c,d| next d.allow! if c.claims[:sub] == 'abcdef'; d.skip! }),
      ]
    end

    it "returns a session" do
      expect(result.claims_result.decision).not_to be_nil
      expect(result.authn_result.allowed).to eq(true)
      expect(result.session_data.claims).to eq(sub: 'abcdef', preferred_username: 'himari')
      expect(result.session_data.user_data).to eq(foo: :bar)
    end
  end

  describe "authn denial case" do
    let(:claims_rules) do
      [
        Himari::Rule.new(name: 'claims', block: proc { |c,d| d.initialize_claims!(sub: c.auth[:id]); d.continue! }),
      ]
    end

    let(:authn_rules) do
      [
        Himari::Rule.new(name: 'deny', block: proc { |c,d| d.deny! }),
      ]
    end

    it "raises UnauthorizedError" do
      expect { result }.to raise_error(Himari::Services::UpstreamAuthentication::UnauthorizedError)
    end
  end

  describe "no claims case" do
    let(:claims_rules) do
      [
      ]
    end

    let(:authn_rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |c,d| d.allow! }),
      ]
    end

    it "raises UnauthorizedError" do
      expect { result }.to raise_error(Himari::Services::UpstreamAuthentication::UnauthorizedError)
    end
  end
end
