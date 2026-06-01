# frozen_string_literal: true

require 'himari/item_provider'

module Himari
  module ItemProviders
    # Looks up dynamically registered clients from storage and presents them to the OIDC
    # endpoints as plain ClientRegistration objects. Lookups always carry an id hint; without
    # one this returns nothing (there is no list operation). Expired registrations are filtered
    # out here so backends without TTL (Memory, Filesystem) and DynamoDB's delayed TTL both
    # fail closed.
    class Storage
      include Himari::ItemProvider

      # @param storage [Himari::Storages::Base]
      # @param skip_consent [Boolean] applied to every dynamic client this provider resolves
      def initialize(storage:, skip_consent: false)
        @storage = storage
        @skip_consent = skip_consent
      end

      def collect(id: nil, **_hint)
        return [] unless id

        client = @storage.find_dynamic_client(id)
        client&.active? ? [client.to_client_registration(skip_consent: @skip_consent)] : []
      end
    end
  end
end
