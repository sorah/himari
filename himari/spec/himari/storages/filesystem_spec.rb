# frozen_string_literal: true

require 'spec_helper'
require 'himari/storages/filesystem'
require 'tmpdir'

RSpec.describe Himari::Storages::Filesystem do
  around do |example|
    Dir.mktmpdir do |dir|
      @dir = dir
      example.run
    end
  end

  subject(:storage) { described_class.new(@dir) }

  def stored_files
    Dir.glob(File.join(@dir, '**', '*'), File::FNM_DOTMATCH).reject { |f| File.directory?(f) }.map { |f| f.delete_prefix("#{@dir}/") }
  end

  describe "key encoding" do
    context "with hex_path: false (default)" do
      it "stores plain keys as-is for backward compatibility" do
        storage.send(:write, 'authz', 'plainkey', {foo: 1})
        expect(stored_files).to eq(%w(authz/plainkey))
        expect(storage.send(:read, 'authz', 'plainkey')).to eq({foo: 1})
      end

      it "hex-encodes keys containing a path separator to prevent traversal" do
        storage.send(:write, 'authz', '../../evil', {foo: 2})
        expect(stored_files).to eq(%W(authz/#{"../../evil".unpack1("H*")}))
        expect(storage.send(:read, 'authz', '../../evil')).to eq({foo: 2})

        storage.send(:delete, 'authz', '../../evil')
        expect(stored_files).to eq([])
      end

      it "reads files written before hex-encoding was introduced" do
        Dir.mkdir(File.join(@dir, 'authz'))
        File.write(File.join(@dir, 'authz', 'legacy'), JSON.generate(foo: 3))
        expect(storage.send(:read, 'authz', 'legacy')).to eq({foo: 3})
      end
    end

    context "with hex_path: true" do
      subject(:storage) { described_class.new(@dir, hex_path: true) }

      it "hex-encodes all keys" do
        storage.send(:write, 'authz', 'plainkey', {foo: 4})
        expect(stored_files).to eq(%W(authz/#{"plainkey".unpack1("H*")}))
        expect(storage.send(:read, 'authz', 'plainkey')).to eq({foo: 4})

        storage.send(:delete, 'authz', 'plainkey')
        expect(stored_files).to eq([])
      end
    end
  end
end
