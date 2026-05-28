# frozen_string_literal: true

require 'spec_helper'
require 'himari/decisions/authentication'
require 'himari/rule'
require 'himari/rule_processor'

RSpec.describe Himari::Decisions::Authentication do
  describe "Context grant_type predicates" do
    it "treats :initial and nil as initial" do
      c = described_class::Context.new(grant_type: :initial)
      expect(c.initial?).to eq(true)
      expect(c.refresh?).to eq(false)

      c2 = described_class::Context.new(grant_type: nil)
      expect(c2.initial?).to eq(true)
    end

    it "treats :refresh_token as refresh" do
      c = described_class::Context.new(grant_type: :refresh_token)
      expect(c.refresh?).to eq(true)
      expect(c.initial?).to eq(false)
    end
  end

  describe "refresh_info setter" do
    it "is preserved through evolve()" do
      d = described_class.new
      d.refresh_info = {token: 'x'}
      d2 = d.evolve('next-rule')
      expect(d2.refresh_info).to eq(token: 'x')
    end

    it "survives a RuleProcessor pipeline" do
      rule1 = Himari::Rule.new(name: 'set', block: proc { |_c, d|
        d.refresh_info = {sub: 'abc'}
        d.allow!
      })
      result = Himari::RuleProcessor.new(described_class::Context.new(grant_type: :initial), described_class.new).run([rule1])
      expect(result.allowed).to eq(true)
      expect(result.decision.refresh_info).to eq(sub: 'abc')
    end
  end
end
