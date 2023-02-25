require 'spec_helper'
require 'himari/decisions/claims'

RSpec.describe Himari::Decisions::Claims do
  subject(:decision) { described_class.new }

  describe "#claims" do
    it "raises error when uninitialized" do
      expect{ decision.claims }.to raise_error(Himari::Decisions::Claims::UninitializedError)
      expect{ decision.user_data }.to raise_error(Himari::Decisions::Claims::UninitializedError)
    end

    it "does not raise error when initialized" do
      decision.initialize_claims!(foo: :bar)
      expect(decision.claims).to eq(foo: :bar)
      expect(decision.user_data).to eq({})
    end
  end

  describe "#initialize_claims!" do
    it "raises error when attempted reinitialization" do
      decision.initialize_claims!(foo: :bar)
      expect { decision.initialize_claims!(hoge: :huga) }.to raise_error(Himari::Decisions::Claims::AlreadyInitializedError)
    end
  end
end
