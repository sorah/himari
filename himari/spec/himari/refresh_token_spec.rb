# frozen_string_literal: true

require 'spec_helper'
require 'himari/refresh_token'

RSpec.describe Himari::RefreshToken do
  describe ".make" do
    subject(:r) do
      described_class.make(
        client_id: 'cli',
        claims: {sub: 'c'},
        session_handle: 'sess',
        openid: true,
        lifetime: 7200,
      )
    end

    specify "populates fields" do
      expect(r.client_id).to eq('cli')
      expect(r.claims).to eq(sub: 'c')
      expect(r.openid).to eq(true)
      expect(r.session_handle).to eq('sess')
      expect(r.handle).to be_a(String)
      expect(r.secret).to be_a(String)
      expect(r.expiry).to be > Time.now.to_i
    end

    specify "format/parse round-trip" do
      parsed = described_class.parse(r.format.to_s)
      expect(parsed.handle).to eq(r.handle)
      expect(parsed.secret).to eq(r.secret)
    end

    specify "as_json round-trip" do
      restored = described_class.new(**JSON.parse(JSON.dump(r.as_json), symbolize_names: true))
      expect(restored.handle).to eq(r.handle)
      expect(restored.client_id).to eq(r.client_id)
      expect(restored.session_handle).to eq(r.session_handle)
      expect(restored.openid).to eq(true)
      expect(restored.verify_secret!(r.secret)).to eq(true)
    end

    specify "starts at version 1 with no previous secret" do
      expect(r.version).to eq(1)
      expect(r.secret_hash_prev).to be_nil
      expect(r.as_json).to include(version: 1, secret_hash_prev: nil)
      expect(r.updated_at).to be_a(Integer)
    end

    specify "as_log omits secrets and reports prev_secret_set" do
      expect(r.as_log.keys).to contain_exactly(:handle, :client_id, :claims, :session_handle, :openid, :expiry, :version, :updated_at, :prev_secret_set)
      expect(r.as_log).to include(prev_secret_set: false)
    end
  end

  describe "#rotate" do
    subject(:original) do
      described_class.make(client_id: 'cli', claims: {sub: 'c'}, session_handle: 'sess', openid: true, lifetime: 7200)
    end

    subject(:rotated) do
      original.verify_secret!(original.secret)
      original.rotate(claims: {sub: 'c2'}, openid: true, lifetime: 3600, now: Time.at(1_700_000_000))
    end

    specify "raises without a prior verify!" do
      expect { original.rotate(claims: {sub: 'c2'}, openid: true, lifetime: 3600) }.to raise_error(Himari::TokenString::SecretMissing)
    end

    specify "keeps the handle, bumps version, slides expiry" do
      expect(rotated.handle).to eq(original.handle)
      expect(rotated.version).to eq(original.version + 1)
      expect(rotated.updated_at).to eq(1_700_000_000)
      expect(rotated.expiry).to eq(1_700_000_000 + 3600)
      expect(rotated.claims).to eq(sub: 'c2')
    end

    specify "issues a fresh secret and keeps the presented secret valid as previous" do
      expect(rotated.secret).not_to eq(original.secret)
      expect(rotated.verify_secret!(rotated.secret)).to eq(true)
      # the secret the client just presented stays valid (the lost-response window)
      expect(described_class.new(**JSON.parse(JSON.dump(rotated.as_json), symbolize_names: true)).verify_secret!(original.secret)).to eq(true)
    end
  end
end
