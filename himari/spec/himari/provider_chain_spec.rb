require 'spec_helper'
require 'himari/provider_chain'
require 'himari/item_providers/static'

RSpec.describe Himari::ProviderChain do
  class DummyItem
    def initialize(str)
      @str = str
    end
    attr_reader :str
    def match_hint?(str: nil)
      if str
        str === @str
      else
        true
      end
    end
  end

  let(:provider1) { Himari::ItemProviders::Static.new([DummyItem.new('a'), DummyItem.new('b')]) }
  let(:provider2) { Himari::ItemProviders::Static.new([DummyItem.new('c')]) }

  let(:chain) { described_class.new([provider1, provider2]) }

  describe "#collect" do
    specify do
      expect(provider1).to receive(:collect).with(str: 'b').and_call_original
      expect(provider2).to receive(:collect).with(str: 'b').and_call_original

      expect(chain.collect(str: 'b').map(&:str)).to eq(%w(a b c))
    end
  end

  describe "#find" do
    specify do
      expect(provider1).to receive(:collect).with(str: 'b').and_call_original
      expect(chain.find(str: 'b')&.str).to eq('b')
    end

    specify do
      expect(provider1).to receive(:collect).with(str: 'c').and_call_original
      expect(provider2).to receive(:collect).with(str: 'c').and_call_original
      expect(chain.find(str: 'c')&.str).to eq('c')
    end

    specify do
      expect(chain.find(str: 'x')).to eq(nil)
    end
  end
end
