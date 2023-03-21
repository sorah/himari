require 'spec_helper'

RSpec.describe Himari::IdToken do
  let(:t) { Time.now }

  let(:nonce) { nil }
  let(:access_token) { nil }

  let(:authz) { double('authz', claims: {sub: 'chihiro'}, client_id: 'testclient', nonce: nonce, lifetime: 900) }
  let(:id_token) { described_class.from_authz(authz, issuer: 'https://test.invalid', signing_key: double('key', hash_function: Digest::SHA256), access_token: access_token, time: t) }

  describe "#final_claims" do
    specify do
      expect(id_token.final_claims).to eq(
        sub: 'chihiro',
        iss: 'https://test.invalid',
        aud: 'testclient',
        iat: t.to_i,
        nbf: t.to_i,
        exp: t.to_i + 900,
      )
    end

    context "with nonce" do
      let(:nonce) { 'foo' }
      specify do
        expect(id_token.final_claims[:nonce]).to eq('foo')
      end
    end

    # https://openid.net/specs/openid-connect-core-1_0.html#id_token-tokenExample
    context "with access_token" do
      let(:access_token) { 'jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y' }
      specify do
        expect(id_token.final_claims[:at_hash]).to eq('77QmUPtjPfzWtF2AnpK9RQ')
      end
    end
  end
end
