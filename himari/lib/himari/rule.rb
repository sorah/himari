module Himari
  Rule = Struct.new(:name, :block, keyword_init: true) do
    def call(context, decision)
      block.call(context, decision)
    end
  end
end
