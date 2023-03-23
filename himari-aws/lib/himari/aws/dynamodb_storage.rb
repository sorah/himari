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

      private def write(kind, key, content, overwrite: false)
        pk = "storage:#{kind}:#{key}"
        payload = {
          content_json: JSON.pretty_generate(content),
          ttl: content[:ttl] || content[:expiry],
        }
        @client.update_item(
          table_name: @table_name,
          key: {
            'pk' => pk,
            'sk' => pk,
          },
          # #{payload.each_key.map { |k| "##{k} = :#{k}" }.join(', ')}
          update_expression: <<~EOS,
          SET
            #content_json = :content_json
          #{payload[:ttl] ? ", #ttl = :ttl" : "REMOVE #ttl"}
          EOS
          condition_expression: overwrite ? nil : 'attribute_not_exists(pk)',
          expression_attribute_names: payload.each_key.map { |k| ["##{k}", k] }.to_h,
          expression_attribute_values: payload.transform_keys { ":#{_1}" },
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

        return nil unless item
        JSON.parse(item.fetch('content_json'), symbolize_names: true)
      end

      private def delete(kind, key)
        pk = "storage:#{kind}:#{key}"
        @client.delete_item(
          table_name: @table_name,
          key: {'pk' => pk, 'sk' => pk}
        )
        nil
      end
    end
  end
end
