# frozen_string_literal: true

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
      expect(code.expiry).to eq((t + 900).to_i)
    end
  end

  describe "session_handle and offline_access" do
    specify "round-trip through as_json" do
      code = described_class.make(client_id: 'cli', claims: {sub: 'c'}, scopes: %w(openid profile offline_access), openid: true, offline_access: true, session_handle: 'sess', redirect_uri: 'https://r.invalid/cb', lifetime: Himari::LifetimeValue.from_integer(60))
      json = JSON.parse(JSON.dump(code.as_json), symbolize_names: true)
      restored = described_class.new(**json)
      expect(restored.session_handle).to eq('sess')
      expect(restored.offline_access).to eq(true)
      expect(restored.openid).to eq(true)
      expect(restored.scopes).to eq(%w(openid profile offline_access))
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
      let(:code) { described_class.new(code: '', code_challenge: 'f' * 100, code_challenge_method: 'plain') }

      specify do
        expect(code.pkce?).to eq(true)
        expect(code.pkce_valid_request?).to eq(true)
      end
    end
  end
end
