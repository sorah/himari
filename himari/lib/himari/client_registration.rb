require 'digest/sha2'

module Himari
  class ClientRegistration
    def initialize(name:, id:, secret: nil, secret_hash: nil, redirect_uris:, preferred_key_group: nil)
      @name = name
      @id = id
      @secret = secret
      @secret_hash = secret_hash
      @redirect_uris = redirect_uris
      @preferred_key_group = preferred_key_group

      raise ArgumentError, "name starts with '_' is reserved" if @name&.start_with?('_')
      raise ArgumentError, "either secret or secret_hash must be present" if !@secret && !@secret_hash
    end

    attr_reader :name, :id, :redirect_uris, :preferred_key_group

    def secret_hash
      @secret_hash ||= Digest::SHA384.hexdigest(secret)
    end

    def match_secret?(given_secret)
      if @secret
        Rack::Utils.secure_compare(@secret, given_secret)
      else
        dgst = [secret_hash].pack('H*')
        Rack::Utils.secure_compare(dgst, Digest::SHA384.digest(given_secret))
      end
    end

    def as_log
      {name: name, id: id}
    end

    def match_hint?(id: nil)
      result = true

      result &&= if id
        id == self.id
      else
        true
      end

      result
    end
  end
end
