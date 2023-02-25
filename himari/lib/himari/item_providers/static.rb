require 'himari/item_provider'

module Himari
  module ItemProviders
    class Static
      include Himari::ItemProvider

      # @param items [Array<Object>] List of static configuration items
      def initialize(items)
        @items = items.dup.freeze
      end

      attr_reader :items

      def collect(**_hint)
        @items
      end
    end
  end
end
