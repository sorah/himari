# frozen_string_literal: true

require 'himari/storages/base'
require 'aws-sdk-dynamodb'

module Himari
  module Aws
    class DynamodbStorage
      include Himari::Storages::Base

      # @param client [Aws::DynamoDB::Client]
      # @param table_name [String] name of DynamoDB table with hash=pk/range=sk key.
      # @param consistent_read [Boolean] use consitent read when querying. default to true.
      def initialize(client: ::Aws::DynamoDB::Client.new, table_name:, consistent_read: true)
        @client = client
        @table_name = table_name
        @consistent_read = consistent_read
      end

      attr_reader :client, :table_name

      def consistent_read?; !!@consistent_read; end

      private def write(kind, key, content, overwrite: false, if_version: nil)
        pk = "storage:#{kind}:#{key}"
        # version and updated_at are mirrored to top-level attributes (besides living inside
        # content_json) so the refresh-token compare-and-swap can reference them in a condition.
        attrs = {
          content_json: JSON.pretty_generate(content),
          version: content[:version],
          updated_at: content[:updated_at],
        }.compact
        ttl = content[:ttl] || content[:expiry]
        attrs[:ttl] = ttl if ttl

        update_expression = +"SET #{attrs.keys.map { |k| "##{k} = :#{k}" }.join(", ")}"
        update_expression << "\nREMOVE #ttl" unless attrs.key?(:ttl)

        expression_attribute_names = attrs.keys.to_h { |k| ["##{k}", k.to_s] }
        expression_attribute_names['#ttl'] = 'ttl' unless attrs.key?(:ttl)
        expression_attribute_values = attrs.transform_keys { ":#{_1}" }

        condition_expression =
          if if_version
            expression_attribute_names['#version'] = 'version'
            expression_attribute_values[':expected_version'] = if_version
            'attribute_exists(pk) AND #version = :expected_version'
          elsif !overwrite
            'attribute_not_exists(pk)'
          end

        @client.update_item(
          table_name: @table_name,
          key: {
            'pk' => pk,
            'sk' => pk,
          },
          update_expression: update_expression,
          condition_expression: condition_expression,
          expression_attribute_names: expression_attribute_names,
          expression_attribute_values: expression_attribute_values,
        )
        nil
      rescue ::Aws::DynamoDB::Errors::ConditionalCheckFailedException
        raise Himari::Storages::Base::Conflict
      end

      private def read(kind, key)
        pk = "storage:#{kind}:#{key}"
        item = @client.query(
          table_name: @table_name,
          select: 'ALL_ATTRIBUTES',
          limit: 1,
          key_condition_expression: 'pk = :pk AND sk = :sk',
          expression_attribute_values: {":pk" => pk, ":sk" => pk},
          consistent_read: consistent_read?,
        ).items.first

        return unless item

        JSON.parse(item.fetch('content_json'), symbolize_names: true)
      end

      private def delete(kind, key)
        pk = "storage:#{kind}:#{key}"
        @client.delete_item(
          table_name: @table_name,
          key: {'pk' => pk, 'sk' => pk},
        )
        nil
      end
    end
  end
end
