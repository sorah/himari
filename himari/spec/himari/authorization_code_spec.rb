require 'spec_helper'
require 'himari/authorization_code'
require 'base64'

RSpec.describe Himari::AuthorizationCode do
  describe ".make" do
    specify do
      t = Time.now
      allow(Time).to receive(:now).and_return(t)

      code = described_class.make
      expect(code.code).to be_a(String)
      expect(code.expiry).to eq((t+900).to_i)
    end
  end

  describe "pkce" do
    context "with no pkce" do
      let(:code) { described_class.new(code: '', code_challenge: nil, code_challenge_method: nil) }
      specify do
        expect(code.pkce?).to eq(false)
      end
    end

    context "with valid pkce S256" do
      let(:code) { described_class.new(code: '', code_challenge: Base64.urlsafe_encode64(Digest::SHA256.digest('x'), padding: false), code_challenge_method: 'S256') }

      specify do
        expect(code.pkce?).to eq(true)
        expect(code.pkce_valid_request?).to eq(true)
      end
    end

    context "with invalid pkce S256" do
      let(:code) { described_class.new(code: '', code_challenge: 'x', code_challenge_method: 'S256') }

      specify do
        expect(code.pkce?).to eq(true)
        expect(code.pkce_valid_request?).to eq(false)
      end
    end

    context "with valid pkce plain" do
      let(:code) { described_class.new(code: '', code_challenge: 'f'*100, code_challenge_method: 'plain') }

      specify do
        expect(code.pkce?).to eq(true)
        expect(code.pkce_valid_request?).to eq(true)
      end
    end
  end
end
