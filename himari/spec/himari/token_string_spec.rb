# frozen_string_literal: true

require 'spec_helper'
require 'himari/token_string'

RSpec.describe Himari::TokenString do
  class TestToken
    include Himari::TokenString

    def initialize(attr: nil, handle: nil, secret: nil, secret_hash: nil, secret_hash_prev: nil, expiry: nil)
      @attr = attr
      @handle = handle
      @secret = secret
      @secret_hash = secret_hash
      @secret_hash_prev = secret_hash_prev
      @expiry = expiry
      @verification = nil
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
      expect(Himari::TokenString::Format).to receive(:parse).with('thdr', 'thdr.aaa.bbb')
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
      subject { TestToken.new(attr: 1, secret: 'himitsu', expiry: Time.now.to_i + 86400) }

      specify { expect(subject.verify_secret!('himitsu')).to eq(true) }
      specify { expect { subject.verify_secret!('incorrect') }.to raise_error(Himari::TokenString::SecretIncorrect) }
    end

    context 'with secret_hash' do
      subject { TestToken.new(attr: 2, secret_hash: Base64.urlsafe_encode64(Digest::SHA384.digest('himitsu')), expiry: Time.now.to_i + 86400) }

      specify { expect(subject.verify_secret!('himitsu')).to eq(true) }
      specify { expect { subject.verify_secret!('incorrect') }.to raise_error(Himari::TokenString::SecretIncorrect) }
    end

    context 'with a previous secret hash' do
      subject do
        TestToken.new(
          attr: 4,
          secret_hash: Himari::TokenString.hash_secret('current'),
          secret_hash_prev: Himari::TokenString.hash_secret('previous'),
          expiry: Time.now.to_i + 86400,
        )
      end

      specify "matches the current secret" do
        expect(subject.verify_secret!('current')).to eq(true)
        expect(subject.verification.via).to eq(:current)
        expect(subject.verification.secret_hash).to eq(subject.secret_hash)
      end

      specify "matches the previous secret" do
        expect(subject.verify_secret!('previous')).to eq(true)
        expect(subject.verification.via).to eq(:previous)
        expect(subject.verification.secret_hash).to eq(subject.secret_hash_prev)
      end

      specify "rejects a secret matching neither" do
        expect { subject.verify_secret!('neither') }.to raise_error(Himari::TokenString::SecretIncorrect)
      end
    end

    context 'with a malformed stored hash' do
      subject { TestToken.new(attr: 5, secret_hash: '!!! not base64 !!!', expiry: Time.now.to_i + 86400) }

      specify "raises SecretIncorrect rather than ArgumentError" do
        expect { subject.verify_secret!('whatever') }.to raise_error(Himari::TokenString::SecretIncorrect)
      end
    end
  end

  describe "#verify_expiry!" do
    subject { TestToken.new(attr: 3, secret: nil, expiry: expiry) }

    context "with future expiry" do
      let(:expiry) { Time.now.to_i + 86400 }
      specify { expect { subject.verify_expiry! }.not_to raise_error }
    end

    context "with past expiry" do
      let(:expiry) { Time.now.to_i - 1 }
      specify { expect { subject.verify_expiry! }.to raise_error(Himari::TokenString::TokenExpired) }
    end
  end
end
