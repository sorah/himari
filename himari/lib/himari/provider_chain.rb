module Himari
  class ProviderChain
    # @param providers [Array<ItemProvider>]
    def initialize(providers)
      @providers = providers
    end

    attr_reader :providers

    def find(**hint, &block)
      block ||= proc { |i,h| i.match_hint?(**h) } # ItemProvider#collect doesn't guarantee exact matches, so do exact match by match_hint?
      @providers.each do |provider|
        provider.collect(**hint).each do |item|
          return item if block.call(item, hint)
        end
      end
      nil
    end

    def collect(**hint)
      @providers.flat_map do |provider|
        provider.collect(**hint)
      end
    end
  end
end
