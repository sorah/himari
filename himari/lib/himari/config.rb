module Himari
  class Config
    def initialize(issuer:, storage:, providers: [])
      @issuer = issuer
      @providers = providers
      @storage = storage
    end

    attr_reader :issuer, :providers, :storage
  end
end
