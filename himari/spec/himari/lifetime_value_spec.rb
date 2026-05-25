# frozen_string_literal: true

require 'spec_helper'
require 'himari/lifetime_value'

RSpec.describe Himari::LifetimeValue do
  describe ".from_integer" do
    it "leaves refresh_token nil" do
      v = described_class.from_integer(100)
      expect(v.access_token).to eq(100)
      expect(v.id_token).to eq(100)
      expect(v.code).to be_nil
      expect(v.refresh_token).to be_nil
    end
  end

  describe "#as_json round-trip" do
    it "preserves refresh_token" do
      v = described_class.new(access_token: 60, id_token: 60, code: 30, refresh_token: 7200)
      restored = described_class.new(**JSON.parse(JSON.dump(v.as_json), symbolize_names: true))
      expect(restored.access_token).to eq(60)
      expect(restored.refresh_token).to eq(7200)
    end
  end

  describe "#as_log" do
    it "drops nil refresh_token" do
      v = described_class.from_integer(60)
      expect(v.as_log.key?(:refresh_token)).to eq(false)
    end

    it "includes refresh_token when set" do
      v = described_class.new(access_token: 60, id_token: 60, code: 30, refresh_token: 7200)
      expect(v.as_log[:refresh_token]).to eq(7200)
    end
  end
end
