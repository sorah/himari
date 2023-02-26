require 'spec_helper'
require 'himari/decisions/authorization'

RSpec.describe Himari::Decisions::Authorization do
  subject(:decision) { described_class.new(claims: {}, allowed_claims: []) }

  describe "#output" do
    before do
      decision.claims.merge!(a: 1, b: 2)
      decision.allowed_claims.push(:a, :c)
    end

    it "filters claims based on allowed_claims" do
      expect(decision.output).to eq(a: 1)
    end
  end
end
