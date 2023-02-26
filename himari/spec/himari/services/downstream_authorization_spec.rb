require 'spec_helper'

require 'himari/services/downstream_authorization'
require 'himari/rule'

RSpec.describe Himari::Services::DownstreamAuthorization do
  let(:rack_request) { double('rack request') }
  let(:session_data) { double('session data', claims: {claims: 1}, user_data: {user_data: 1}) }
  let(:client) { double('client registration') }

  let(:authz_rules) do
    [
      # Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
    ]
  end

  subject(:service) { described_class.new(session: session_data, client: client, request: rack_request, authz_rules: authz_rules) }
  subject(:result) { service.perform }

  describe "nominal case" do
    let(:authz_rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |c,d|
          c.client.ok # mark
          expect(c.claims[:claims]).to eq(1)
          expect(c.user_data[:user_data]).to eq(1)
          expect(c.request).to eq(rack_request)

          expect(d.claims[:claims]).to eq(1)
          d.allowed_claims.push(:claims, :new_claims)
          d.claims[:claims] = 2
          d.claims[:new_claims] = 2
          d.allow!
        }),
      ]
    end

    it "returns an authorization" do
      expect(client).to receive(:ok)
      expect(result.client).to eq(client)
      expect(result.claims).to eq(claims: 2, new_claims: 2)
      expect(result.authz_result.allowed).to eq(true)
    end
  end

  describe "authz denial case" do
    let(:authz_rules) do
      [
        Himari::Rule.new(name: 'deny', block: proc { |c,d| d.deny! }),
      ]
    end

    it "raises ForbiddenError" do
      expect { result }.to raise_error(Himari::Services::DownstreamAuthorization::ForbiddenError)
    end
  end

  describe "no claims case" do
    let(:authz_rules) do
      [
      ]
    end

    it "raises ForbiddenError" do
      expect { result }.to raise_error(Himari::Services::DownstreamAuthorization::ForbiddenError)
    end
  end
end
