require 'spec_helper'
require 'himari/signing_key'

RSpec.describe Himari::SigningKey do
  let(:ec_pkey) { OpenSSL::PKey::EC.new(Himari::Testing::TEST_EC_KEY_PEM, '') }
  let(:rsa_pkey) { OpenSSL::PKey::RSA.new(Himari::Testing::TEST_RSA_KEY_PEM, '') }

  describe "#match_hint?" do
    let(:key) { described_class.new(id: 'kid', pkey: ec_pkey, inactive: true, group: 'a') }

    describe "simple" do
      specify do
        expect(key.match_hint?()).to eq(true)
        expect(key.match_hint?(id: 'kid')).to eq(true)
        expect(key.match_hint?(active: true, group: 'a')).to eq(false)
        expect(key.match_hint?(active: false, group: 'a')).to eq(true)
        expect(key.match_hint?(id: 'kid', group: 'b')).to eq(false)
        expect(key.match_hint?(id: 'kid', active: true)).to eq(false)
        expect(key.match_hint?(id: 'kid', group: 'a', active: false)).to eq(true)
      end
    end
  end

  describe "#alg" do
    describe "inferred" do
      context "with EC256 key" do
        let(:key) { described_class.new(id: 'kid', pkey: ec_pkey) }
        specify { expect(key.alg).to eq('ES256') }
      end

      context "with RSA key" do
        let(:key) { described_class.new(id: 'kid', pkey: rsa_pkey) }
        specify { expect(key.alg).to eq('RS256') }
      end
    end
  end

  describe "#hash_function" do
    describe "inferred" do
      context "with EC256 key" do
        let(:key) { described_class.new(id: 'kid', pkey: ec_pkey) }
        specify { expect(key.hash_function).to eq(Digest::SHA256) }
      end

      context "with RSA key" do
        let(:key) { described_class.new(id: 'kid', pkey: rsa_pkey) }
        specify { expect(key.hash_function).to eq(Digest::SHA256) }
      end
    end
  end

  describe "#ec_crv" do
    context "with EC256 key" do
      let(:key) { described_class.new(id: 'kid', pkey: ec_pkey) }
      specify { expect(key.ec_crv).to eq('P-256') }
    end

    context "with RSA key" do
      let(:key) { described_class.new(id: 'kid', pkey: rsa_pkey) }
      specify { expect { key.ec_crv }.to raise_error(Himari::SigningKey::OperationInvalid) }
    end
  end

  # https://www.rfc-editor.org/rfc/rfc7517#appendix-A.2
  describe "#as_jwk" do
    context "with example EC P-256 key" do
      let(:key) { described_class.new(id: 'example-ec', pkey: ec_pkey) }
      specify { expect(key.as_jwk).to eq(Himari::Testing::TEST_EC_KEY_JWK) }
    end

    context "with example RSA key" do
      let(:key) { described_class.new(id: 'example-rsa', pkey: rsa_pkey) }
      specify { expect(key.as_jwk).to eq(Himari::Testing::TEST_RSA_KEY_JWK) }
    end
  end
end
