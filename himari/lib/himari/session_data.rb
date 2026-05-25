# frozen_string_literal: true

require 'himari/token_string'

module Himari
  class SessionData
    include Himari::TokenString

    def initialize(claims: {}, user_data: {}, refresh_info: nil, handle:, secret: nil, secret_hash: nil, expiry: nil)
      @claims = claims
      @user_data = user_data
      @refresh_info = refresh_info

      @handle = handle
      @secret = secret
      @secret_hash = secret_hash
      @secret_hash_prev = nil
      @expiry = expiry
      @verification = nil
    end

    def self.magic_header
      'hmas'
    end

    def self.default_lifetime
      3600
    end

    attr_reader :claims, :user_data, :refresh_info

    def refreshable?
      !@refresh_info.nil?
    end

    def active?(now: Time.now)
      @expiry.nil? || @expiry > now.to_i
    end

    # Return a copy with selected fields replaced. Reads @secret directly to
    # sidestep TokenString#secret raising SecretMissing for storage-loaded sessions.
    def with(claims: @claims, user_data: @user_data, refresh_info: @refresh_info, expiry: @expiry)
      self.class.new(
        handle: @handle,
        secret: @secret,
        secret_hash: @secret_hash,
        expiry: expiry,
        claims: claims,
        user_data: user_data,
        refresh_info: refresh_info,
      )
    end

    def as_log
      {
        handle: handle,
        claims: claims,
        expiry: expiry,
        refreshable: refreshable?,
      }
    end

    def as_json
      {
        handle: handle,
        secret_hash: secret_hash,
        expiry: expiry,

        claims: claims,
        user_data: user_data,
        refresh_info: refresh_info,
      }
    end
  end
end
