# frozen_string_literal: true

require 'spec_helper'
require 'himari/session_data'

RSpec.describe Himari::SessionData do
  describe "#refreshable?" do
    it "is false when refresh_info nil" do
      s = described_class.make(claims: {sub: 'x'})
      expect(s.refreshable?).to eq(false)
    end

    it "is true when refresh_info present" do
      s = described_class.make(claims: {sub: 'x'}, refresh_info: {token: 'u'})
      expect(s.refreshable?).to eq(true)
    end
  end

  describe "#active?" do
    it "is true when expiry is in the future" do
      s = described_class.new(handle: 'h', secret_hash: 'sh', expiry: 100, claims: {}, user_data: {})
      expect(s.active?(now: Time.at(50))).to eq(true)
    end

    it "is false when expiry has passed" do
      s = described_class.new(handle: 'h', secret_hash: 'sh', expiry: 100, claims: {}, user_data: {})
      expect(s.active?(now: Time.at(100))).to eq(false)
      expect(s.active?(now: Time.at(150))).to eq(false)
    end

    it "is true when expiry is nil (no expiry)" do
      s = described_class.new(handle: 'h', secret_hash: 'sh', expiry: nil, claims: {}, user_data: {})
      expect(s.active?).to eq(true)
    end
  end

  describe "#with" do
    it "returns a copy with overridden fields" do
      s = described_class.make(claims: {sub: 'x'}, user_data: {p: 'a'})
      s2 = s.with(claims: {sub: 'y'}, refresh_info: {t: 1})
      expect(s2.handle).to eq(s.handle)
      expect(s2.claims).to eq(sub: 'y')
      expect(s2.user_data).to eq(p: 'a')
      expect(s2.refresh_info).to eq(t: 1)
      expect(s2.expiry).to eq(s.expiry)
      # secret preserved (would otherwise raise SecretMissing if not)
      expect(s2.format.to_s).to eq(s.format.to_s)
    end

    it "works for storage-loaded sessions (secret nil)" do
      loaded = described_class.new(handle: 'h', secret_hash: 'sh', expiry: 100, claims: {sub: 'x'}, user_data: {}, refresh_info: nil)
      changed = loaded.with(claims: {sub: 'y'}, refresh_info: {t: 1})
      expect(changed.handle).to eq('h')
      expect(changed.secret_hash).to eq('sh')
      expect(changed.claims).to eq(sub: 'y')
      expect(changed.refresh_info).to eq(t: 1)
    end
  end

  describe "as_json round-trip" do
    it "preserves refresh_info" do
      s = described_class.make(claims: {sub: 'x'}, refresh_info: {token: 'u'})
      restored = described_class.new(**JSON.parse(JSON.dump(s.as_json), symbolize_names: true))
      expect(restored.handle).to eq(s.handle)
      expect(restored.claims).to eq(sub: 'x')
      expect(restored.refresh_info).to eq(token: 'u')
      expect(restored.refreshable?).to eq(true)
    end
  end
end
