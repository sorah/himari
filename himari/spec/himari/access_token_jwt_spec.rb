# frozen_string_literal: true

require 'spec_helper'
require 'himari/access_token'
require 'himari/access_token_jwt'
require 'himari/signing_key'

RSpec.describe Himari::AccessTokenJwt do
  let(:t) { Time.now }
  let(:pkey) { OpenSSL::PKey::RSA.new(Himari::Testing::TEST_RSA_KEY_PEM, '') }
  let(:signing_key) { Himari::SigningKey.new(id: 'kid', pkey: pkey, inactive: false, group: 'kagi') }
  let(:scopes) { %w(openid profile) }
  let(:access) { Himari::AccessToken.make(client_id: 'testclient', claims: {sub: 'chihiro'}, scopes: scopes) }

  subject(:jwt) do
    described_class.new(access: access, claims: {sub: 'chihiro', email: 'c@test.invalid'}, client_id: 'testclient', signing_key: signing_key, issuer: 'https://test.invalid', time: t, lifetime: 456)
  end

  describe "#final_claims" do
    specify do
      # https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2 required claims, plus the IdP
      # claims carried verbatim (same set as the ID Token), the granted scope, and hmat.
      expect(jwt.final_claims).to eq(
        sub: 'chihiro',
        email: 'c@test.invalid',
        iss: 'https://test.invalid',
        aud: 'testclient',
        client_id: 'testclient',
        iat: t.to_i,
        nbf: t.to_i,
        exp: t.to_i + 456,
        jti: access.handle,
        scope: 'openid profile',
        hmat: access.format.to_s,
      )
    end

    # https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2.1 — scope is space-delimited.
    context "when no scopes were granted" do
      let(:scopes) { [] }
      it "omits the scope claim" do
        expect(jwt.final_claims).not_to have_key(:scope)
      end
    end

    context "when the IdP claims have no sub" do
      subject(:jwt) do
        described_class.new(access: access, claims: {email: 'c@test.invalid'}, client_id: 'testclient', signing_key: signing_key, issuer: 'https://test.invalid', time: t, lifetime: 456)
      end

      it "fails closed rather than minting a non-conformant token" do
        expect { jwt.final_claims }.to raise_error(described_class::MissingSubject)
      end
    end
  end

  # https://www.rfc-editor.org/rfc/rfc9068.html — assert the on-the-wire token meets the profile
  # so a future change that drops a required claim/header fails here.
  describe "RFC 9068 conformance of the minted token" do
    let(:decoded) { JSON::JWT.decode(jwt.to_jwt, pkey) }

    it "has the at+jwt typ header" do
      expect(decoded.header[:typ]).to eq('at+jwt') # §2.1
    end

    it "is signed with an asymmetric alg (never none)" do
      expect(decoded.header[:alg]).to eq('RS256') # §2.1: asymmetric, not 'none'
      expect(decoded.header[:alg]).not_to eq('none')
    end

    it "carries every required claim" do
      # §2.2 required: iss, exp, aud, sub, client_id, iat, jti
      %i(iss exp aud sub client_id iat jti).each do |claim|
        expect(decoded[claim]).not_to be_nil, "missing required claim #{claim}"
      end
      expect(decoded[:scope]).to eq('openid profile') # §2.2.1
    end
  end

  describe "#to_jwt" do
    let(:decoded) { JSON::JWT.decode(jwt.to_jwt, pkey) }

    it "sets the RFC 9068 typ header and the signing key kid" do
      expect(decoded.header[:typ]).to eq('at+jwt')
      expect(decoded.header[:kid]).to eq('kid')
    end

    it "is verifiable with the signing key and carries hmat" do
      expect(decoded[:sub]).to eq('chihiro')
      expect(decoded['hmat']).to eq(access.format.to_s)
    end
  end
end
