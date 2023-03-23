require 'spec_helper'
require 'himari/token_string'

RSpec.describe Himari::TokenString do
  class TestToken
    include Himari::TokenString

    def initialize(attr: nil, handle: nil, secret: nil, secret_hash: nil, expiry: nil)
      @attr = attr
      @handle = handle
      @secret = secret
      @secret_hash = secret_hash
      @expiry = expiry
    end

    attr_reader :attr, :expiry

    def self.magic_header
      'thdr'
    end

    def self.default_lifetime
      900
    end

    def as_json
      {
        attr: attr,
        handle: handle,
        secret_hash: secret_hash,
        expiry: expiry,
      }
    end
  end

  describe Himari::TokenString::Format do
    describe ".parse" do
      let(:given_token) { nil }
      subject(:format) { described_class.parse('hdr', given_token) }
      subject { [format.handle, format.secret] }

      context "with nominal" do
        let(:given_token) { 'hdr.abc.def' }
        it { is_expected.to eq(['abc', 'def']) }
      end

      context "with empty" do
        let(:given_token) { '' }
        specify { expect { format }.to raise_error(Himari::TokenString::InvalidFormat) }
      end

      context "with missing parts" do
        let(:given_token) { 'hdr.b' }
        specify { expect { format }.to raise_error(Himari::TokenString::InvalidFormat) }
      end

      context "with excess parts" do
        let(:given_token) { 'hdr.b.c.d' }
        specify { expect { format }.to raise_error(Himari::TokenString::InvalidFormat) }
      end

      context "with invalid header" do
        let(:given_token) { 'eyJ.json.tabun' }
        specify { expect { format }.to raise_error(Himari::TokenString::InvalidFormat) }
      end
    end

    describe "#to_s" do
      subject { described_class.new(header: 'hdr', handle: 'abc', secret: 'def').to_s }
      it { is_expected.to eq('hdr.abc.def') }
    end
  end

  describe ".parse" do
    specify do
      expect(Himari::TokenString::Format).to receive(:parse).with('thdr','thdr.aaa.bbb')
      TestToken.parse('thdr.aaa.bbb')
    end
  end

  describe "make roundtrip" do
    subject { TestToken.make(attr: :value) }

    specify do
      expect(subject.attr).to eq(:value)
      expect(subject.expiry).to be_a(Integer)
      expect(subject.handle).to be_a(String)
      expect(subject.secret).to be_a(String)
    end

    specify do
      parse = TestToken.parse(subject.format.to_s)
      expect(parse.handle).to eq(subject.handle)
      expect(parse.secret).to eq(subject.secret)
    end
  end

  describe "#verify_secret!" do
    context 'with secret' do
      subject { TestToken.new(attr: 1, secret: 'himitsu', expiry: Time.now.to_i+86400) }

      specify { expect(subject.verify_secret!('himitsu')).to eq(true) }
      specify { expect { subject.verify_secret!('incorrect') }.to raise_error(Himari::TokenString::SecretIncorrect) }
    end

    context 'with secret_hash' do
      subject { TestToken.new(attr: 2, secret_hash: Base64.urlsafe_encode64(Digest::SHA384.digest('himitsu')), expiry: Time.now.to_i+86400) }

      specify { expect(subject.verify_secret!('himitsu')).to eq(true) }
      specify { expect { subject.verify_secret!('incorrect') }.to raise_error(Himari::TokenString::SecretIncorrect) }
    end
  end

  describe "#verify_expiry!" do
    subject { TestToken.new(attr: 3, secret: nil, expiry: expiry) }

    context "with future expiry" do
      let(:expiry) { Time.now.to_i + 86400 }
      specify { expect { subject.verify_expiry!() }.not_to raise_error }
    end

    context "with past expiry" do
      let(:expiry) { Time.now.to_i - 1 }
      specify { expect { subject.verify_expiry!() }.to raise_error(Himari::TokenString::TokenExpired) }
    end
  end

end
