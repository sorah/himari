# frozen_string_literal: true

require 'spec_helper'
require 'himari/decisions/claims'

RSpec.describe Himari::Decisions::Claims do
  subject(:decision) { described_class.new }

  describe "#claims" do
    it "raises error when uninitialized" do
      expect { decision.claims }.to raise_error(Himari::Decisions::Claims::UninitializedError)
      expect { decision.user_data }.to raise_error(Himari::Decisions::Claims::UninitializedError)
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

  describe "Context#provider" do
    it "is the supplied value (sourced by caller from auth or session.user_data)" do
      c = described_class::Context.new(auth: {provider: 'test'}, provider: 'test')
      expect(c.provider).to eq('test')
    end

    it "is the supplied value on refresh too (auth nil, provider from session.user_data)" do
      c = described_class::Context.new(auth: nil, provider: 'test', grant_type: :refresh_token, refresh_info: {sub: 'x'})
      expect(c.provider).to eq('test')
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

  describe ":deny effect" do
    it "is allowed" do
      decision.initialize_claims!(sub: 'x')
      d = decision.evolve('r')
      expect { d.deny!("upstream refused refresh") }.not_to raise_error
      expect(d.effect).to eq(:deny)
    end
  end

  describe "#refresh_info accessor" do
    it "round-trips through evolve" do
      decision.initialize_claims!(sub: 'x')
      decision.refresh_info = {token: 'u'}
      evolved = decision.evolve('r')
      expect(evolved.refresh_info).to eq(token: 'u')
    end

    it "is initially nil" do
      expect(decision.refresh_info).to be_nil
    end
  end

  describe "#as_log" do
    it "redacts refresh_info to a boolean" do
      decision.initialize_claims!(sub: 'x')
      decision.refresh_info = {token: 'secret-upstream-refresh'}
      log = decision.as_log
      expect(log).to include(refresh_info_set: true)
      expect(log.to_s).not_to include('secret-upstream-refresh')
    end

    it "reports refresh_info_set: false when unset" do
      decision.initialize_claims!(sub: 'x')
      expect(decision.as_log).to include(refresh_info_set: false)
    end
  end
end
