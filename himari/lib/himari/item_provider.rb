module Himari
  module ItemProvider
    # :nocov:
    # Return items searched by hints. This method can perform fuzzy match with hints. OTOH is not expected to return exact match results.
    # Use Item#match_hint? to do exact match in later process. See also: ProviderChain
    def collect(**hints) 
      raise NotImplementedError
    end
    # :nocov:
  end
end
