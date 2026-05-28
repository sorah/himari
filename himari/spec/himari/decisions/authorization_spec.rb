# frozen_string_literal: true

require 'spec_helper'
require 'himari/decisions/authorization'

RSpec.describe Himari::Decisions::Authorization do
  subject(:decision) { described_class.new(claims: {}, allowed_claims: []) }

  describe "#output_claims" do
    before do
      decision.claims.merge!(a: 1, b: 2)
      decision.allowed_claims.push(:a, :c)
    end

    it "filters claims based on allowed_claims" do
      expect(decision.output_claims).to eq(a: 1)
    end
  end

  describe "Context grant_type predicates" do
    it "treats :initial and nil as initial" do
      expect(described_class::Context.new(grant_type: :initial).initial?).to eq(true)
      expect(described_class::Context.new(grant_type: nil).initial?).to eq(true)
    end

    it "treats :refresh_token as refresh" do
      c = described_class::Context.new(grant_type: :refresh_token)
      expect(c.refresh?).to eq(true)
      expect(c.initial?).to eq(false)
    end
  end
end
