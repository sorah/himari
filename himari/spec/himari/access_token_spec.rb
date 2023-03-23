require 'spec_helper'
require 'himari/access_token'
require 'base64'
require 'digest/sha2'


RSpec.describe Himari::AccessToken do
  describe Himari::AccessToken::Format do
    describe ".parse" do
      let(:given_token) { nil }
      subject(:format) { Himari::AccessToken.parse(given_token) }
      subject { [format.handle, format.secret] }

      context "with nominal" do
        let(:given_token) { 'hmat.abc.def' }
        it { is_expected.to eq(['abc', 'def']) }
      end

      context "with empty" do
        let(:given_token) { '' }
        specify { expect { format }.to raise_error(Himari::AccessToken::InvalidFormat) }
      end

      context "with missing parts" do
        let(:given_token) { 'hmat.b' }
        specify { expect { format }.to raise_error(Himari::AccessToken::InvalidFormat) }
      end

      context "with excess parts" do
        let(:given_token) { 'hmat.b.c.d' }
        specify { expect { format }.to raise_error(Himari::AccessToken::InvalidFormat) }
      end

      context "with invalid header" do
        let(:given_token) { 'eyJ.json.tabun' }
        specify { expect { format }.to raise_error(Himari::AccessToken::InvalidFormat) }
      end
    end

    describe "#to_s" do
      subject { described_class.new(header: 'hmat', handle: 'abc', secret: 'def').to_s }
      it { is_expected.to eq('hmat.abc.def') }
    end
  end

  describe "make roundtrip" do
    let(:authz) { double('authz', client_id: 'client', claims: {sub: 'chihiro'}) }
    subject { described_class.from_authz(authz) }

    specify do
      expect(subject.client_id).to eq('client')
      expect(subject.claims).to eq({sub: 'chihiro'})
      expect(subject.expiry).to be_a(Integer)
      expect(subject.secret).to be_a(String)
    end

    specify do
      parse = Himari::AccessToken.parse(subject.format.to_s)
      expect(parse.handle).to eq(subject.handle)
      expect(parse.secret).to eq(subject.secret)
    end
  end

  describe "#verify_secret!" do
    context 'with secret' do
      subject { described_class.new(handle: 'abc', secret: 'himitsu', client_id: 'client', claims: {sub: 'chihiro'}, expiry: Time.now.to_i+86400) }

      specify { expect(subject.verify_secret!('himitsu')).to eq(true) }
      specify { expect { subject.verify_secret!('incorrect') }.to raise_error(Himari::AccessToken::SecretIncorrect) }
    end

    context 'with secret_hash' do
      subject { described_class.new(handle: 'abc', secret_hash: Base64.urlsafe_encode64(Digest::SHA384.digest('himitsu')), client_id: 'client', claims: {sub: 'chihiro'}, expiry: Time.now.to_i+86400) }

      specify { expect(subject.verify_secret!('himitsu')).to eq(true) }
      specify { expect { subject.verify_secret!('incorrect') }.to raise_error(Himari::AccessToken::SecretIncorrect) }
    end
  end

  describe "#verify_expiry!" do
    subject { described_class.new(handle: 'abc', secret: 'himitsu', client_id: 'client', claims: {sub: 'chihiro'}, expiry: expiry) }

    context "with future expiry" do
      let(:expiry) { Time.now.to_i + 86400 }
      specify { expect { subject.verify_expiry!() }.not_to raise_error }
    end

    context "with past expiry" do
      let(:expiry) { Time.now.to_i - 86400 }
      specify { expect { subject.verify_expiry!() }.to raise_error(Himari::AccessToken::TokenExpired) }
    end
  end
end
