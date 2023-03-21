require 'spec_helper'
require 'himari/rule_processor'
require 'himari/rule'
require 'himari/decisions/base'

RSpec.describe Himari::RuleProcessor do
  class TestDecision < Himari::Decisions::Base
    def initialize(value: nil, transient_value: nil)
      super()
      @value = value
      @transient_value = transient_value
    end

    def to_evolve_args
      {value: value.dup}
    end

    allow_effects(:allow, :continue, :deny, :skip)
    attr_accessor :value, :transient_value
  end

  let(:test_context) { double('context') }
  let(:initial_decision) { TestDecision.new }
  let(:rules) { raise "undefined" }
  subject(:processor) { described_class.new(test_context, initial_decision) }
  subject(:result) { processor.run(rules) }

  describe "effect" do
    describe "for empty rule set" do
      let(:rules) do
        [
        ]
      end

      it "returns implicit deny" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.explicit_deny).to eq(false)
        expect(result.rule_name).to eq(nil)
        expect(result.decision).to eq(initial_decision)
      end
    end

    describe "for no-effect rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'continue', block: proc { |c,d| d.continue! }),
          Himari::Rule.new(name: 'skip', block: proc { |c,d| d.skip! }),
        ]
      end

      it "returns implicit deny" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.explicit_deny).to eq(false)
        expect(result.rule_name).to eq(nil)
        expect(result.decision.rule_name).to eq('continue')
      end
    end

    describe "for allow rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'allow', block: proc { |c,d| d.allow! }),
        ]
      end

      it "returns allow" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(true)
        expect(result.explicit_deny).to eq(false)
        expect(result.rule_name).to eq('allow')
        expect(result.decision.effect).to eq(:allow)
        expect(result.decision.rule_name).to eq('allow')
      end
    end

    describe "for deny rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'deny', block: proc { |c,d| d.deny! }),
        ]
      end

      it "returns explicit deny" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.explicit_deny).to eq(true)
        expect(result.rule_name).to eq('deny')
        expect(result.decision).to eq(nil)
      end
    end

    describe "for allow-then-deny rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'allow', block: proc { |c,d| d.allow! }),
          Himari::Rule.new(name: 'deny', block: proc { |c,d| d.deny! }),
          Himari::Rule.new(name: 'should-not-be-called', block: proc { |c,d| raise "this should not be called" }),
        ]
      end

      it "stops processing and returns explicit deny" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.explicit_deny).to eq(true)
        expect(result.rule_name).to eq('deny')
        expect(result.decision).to eq(nil)
      end
    end

    describe "for undecided rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'no-decision', block: proc { |c,d| :do_nothing }),
        ]
      end

      it "raises MissingDecisionError" do
        expect { result }.to raise_error(Himari::RuleProcessor::MissingDecisionError)
      end
    end
  end

  describe "decision value" do
    describe "for allow rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'allow', block: proc { |c,d| d.value = :allow; d.allow! }),
        ]
      end

      it "returns continue rule value" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(true)
        expect(result.rule_name).to eq('allow')
        expect(result.decision.rule_name).to eq('allow')
        expect(result.decision.value).to eq(:allow)
      end
    end

    describe "for deny rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'deny', block: proc { |c,d| d.value = :deny; d.deny! }),
        ]
      end

      it "returns no value" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.rule_name).to eq('deny')
        expect(result.decision).to eq(nil)
      end
    end

    describe "for continue rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'continue', block: proc { |c,d| d.value = :continue; d.continue! }),
        ]
      end

      it "returns continue rule value" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.rule_name).to eq(nil)
        expect(result.decision.rule_name).to eq('continue')
        expect(result.decision.value).to eq(:continue)
      end
    end

    describe "for skip rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'skip', block: proc { |c,d| d.value = :skip; d.skip! }),
        ]
      end

      it "returns no rule value" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(false)
        expect(result.rule_name).to eq(nil)
        expect(result.decision.rule_name).to eq(nil)
        expect(result.decision.value).to eq(nil)
      end
    end

    describe "for allow-then-continue rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'allow', block: proc { |c,d| d.value = :allow; d.allow! }),
          Himari::Rule.new(name: 'continue', block: proc { |c,d| expect(d.value).to eq(:allow); d.value = :continue; d.continue! }),
        ]
      end

      it "returns continue rule value" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(true)
        expect(result.rule_name).to eq('allow')
        expect(result.decision.rule_name).to eq('continue')
        expect(result.decision.value).to eq(:continue)
      end
    end

    describe "for skip-and-allow rule set" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'skip', block: proc { |c,d| d.value = :skip; d.skip! }),
          Himari::Rule.new(name: 'allow', block: proc { |c,d| d.allow! }),
        ]
      end

      it "returns no value" do
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(true)
        expect(result.rule_name).to eq('allow')
        expect(result.decision.rule_name).to eq('allow')
        expect(result.decision.value).to eq(nil)
      end
    end

    describe "for allow-then-skip rule set" do
      let(:marker) { double('marker') }
      let(:rules) do
        [
          Himari::Rule.new(name: 'allow', block: proc { |c,d| d.value = :allow; d.allow! }),
          Himari::Rule.new(name: 'skip', block: proc { |c,d| expect(d.value).to eq(:allow); marker.call; d.value = :skip; d.skip! }),
        ]
      end

      it "returns value from allow" do
        expect(marker).to receive(:call)
        expect(result).to be_a(Himari::RuleProcessor::Result)
        expect(result.allowed).to eq(true)
        expect(result.rule_name).to eq('allow')
        expect(result.decision.rule_name).to eq('allow')
        expect(result.decision.value).to eq(:allow)
      end
    end
  end

  # objects not in to_evolve_args
  describe "transient value" do
    let(:rules) do
      [
        Himari::Rule.new(name: 'allow', block: proc { |c,d| raise if d.transient_value; d.transient_value = true; d.allow! }),
        Himari::Rule.new(name: 'continue', block: proc { |c,d| raise if d.transient_value; d.transient_value = true; d.continue! }),
        Himari::Rule.new(name: 'skip', block: proc { |c,d| raise if d.transient_value; d.transient_value = true; d.skip! }),
        Himari::Rule.new(name: 'deny', block: proc { |c,d| raise if d.transient_value; d.transient_value = true; d.deny! }),
      ]
    end

    it "should not be transferred when evolve" do
      expect { result }.not_to raise_error
    end
  end

  describe "invalid effects:" do
    describe "double allow" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'doubleallow', block: proc { |c,d| d.allow!; d.allow!; }),
        ]
      end

      specify { expect { subject }.to raise_error(Himari::Decisions::Base::DecisionAlreadyMade) }
    end

    describe "invalid choice" do
      class TestDecisionLimited < TestDecision
        allow_effects :continue, :skip
      end
      let(:initial_decision) { TestDecisionLimited.new }

      let(:rules) do
        [
          Himari::Rule.new(name: 'invalid', block: proc { |c,d| d.allow! }),
        ]
      end

      specify { expect { subject }.to raise_error(Himari::Decisions::Base::InvalidEffect) }
    end

    describe "allow with suggestion" do
      let(:rules) do
        [
          Himari::Rule.new(name: 'invalid', block: proc { |c,d| d.allow!(nil, suggest: :something) }),
        ]
      end

      specify { expect { subject }.to raise_error(Himari::Decisions::Base::InvalidEffect) }
    end
  end
end
