# frozen_string_literal: true

require 'spec_helper'
require 'himari/access_token'
require 'himari/access_token_jwt'
require 'himari/signing_key'
require 'himari/provider_chain'
require 'himari/item_providers/static'
require 'base64'
require 'digest/sha2'

RSpec.describe Himari::AccessToken do
  describe "make roundtrip" do
    let(:now) { Time.now }
    let(:authz) { double('authz', client_id: 'client', claims: {sub: 'chihiro'}, scopes: %w(openid profile), session_handle: 'sess', lifetime: double('lifetime', access_token: 123)) }
    subject { described_class.from_authz(authz) }

    before do
      expect(Time).to receive(:now).and_return(now)
    end

    specify do
      expect(subject.client_id).to eq('client')
      expect(subject.claims).to eq({sub: 'chihiro'})
      expect(subject.scopes).to eq(%w(openid profile))
      expect(subject.expiry).to eq(now.to_i + 123)
      expect(subject.secret).to be_a(String)
    end

    specify do
      parse = Himari::AccessToken.parse(subject.format.to_s)
      expect(parse.handle).to eq(subject.handle)
      expect(parse.secret).to eq(subject.secret)
    end
  end

  describe ".parse with a JWT access token (RFC 9068)" do
    let(:pkey) { OpenSSL::PKey::RSA.new(Himari::Testing::TEST_RSA_KEY_PEM, '') }
    let(:signing_key) { Himari::SigningKey.new(id: 'kid', pkey: pkey, inactive: false, group: 'kagi') }
    let(:signing_key_provider) { Himari::ProviderChain.new([Himari::ItemProviders::Static.new([signing_key])]) }

    let(:access) { described_class.make(client_id: 'client', claims: {sub: 'chihiro'}) }
    let(:jwt) do
      Himari::AccessTokenJwt.new(access: access, claims: access.claims, client_id: 'client', signing_key: signing_key, issuer: 'https://test.invalid').to_jwt
    end

    it "verifies the signature and returns the embedded opaque token (hmat)" do
      parsed = described_class.parse(jwt, signing_key_provider: signing_key_provider)
      expect(parsed.handle).to eq(access.handle)
      expect(parsed.secret).to eq(access.secret)
    end

    describe "#to_jwt round-trips through .parse" do
      it "renders a JWT whose exp matches the token's own expiry and parses back to itself" do
        str = access.to_jwt(signing_key: signing_key, issuer: 'https://test.invalid')
        expect(JSON::JWT.decode(str, pkey)[:exp]).to eq(access.expiry)

        parsed = described_class.parse(str, signing_key_provider: signing_key_provider)
        expect(parsed.handle).to eq(access.handle)
        expect(parsed.secret).to eq(access.secret)
      end
    end

    it "requires a signing key provider to verify a JWT" do
      expect { described_class.parse(jwt) }.to raise_error(Himari::TokenString::InvalidFormat)
    end

    it "rejects a JWT signed by an unknown key (kid)" do
      empty_provider = Himari::ProviderChain.new([Himari::ItemProviders::Static.new([])])
      expect { described_class.parse(jwt, signing_key_provider: empty_provider) }.to raise_error(Himari::TokenString::InvalidFormat)
    end

    it "rejects a JWT with a tampered signature" do
      tampered = "#{jwt[0...-2]}XX"
      expect { described_class.parse(tampered, signing_key_provider: signing_key_provider) }.to raise_error(Himari::TokenString::InvalidFormat)
    end

    it "rejects a non-JWT, non-opaque string" do
      expect { described_class.parse('not a token', signing_key_provider: signing_key_provider) }.to raise_error(Himari::TokenString::InvalidFormat)
    end
  end
end
