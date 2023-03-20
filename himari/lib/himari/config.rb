require 'logger'
require 'time'
require 'json'
require 'himari/log_line'

module Himari
  class Config
    def initialize(issuer:, storage:, providers: [], log_output: $stdout, log_level: Logger::INFO, preserve_rack_logger: false)
      @issuer = issuer
      @providers = providers
      @storage = storage

      @log_output = log_output
      @log_level = log_level
      @preserve_rack_logger = preserve_rack_logger
    end

    attr_reader :issuer, :providers, :storage, :preserve_rack_logger

    def logger
      @logger ||= Logger.new(@log_output).tap do |l|
        l.level = @log_level
        l.formatter = proc do |severity, datetime, progname, msg|
          log = {time: datetime.xmlschema, severity: severity.to_s, pid: Process.pid}

          case msg
          when Himari::LogLine
            log[:message] = msg.message
            log[:data] = msg.data
          else
            log[:message] = msg.to_s
          end

          "#{JSON.generate(log)}\n"
        end
      end
    end
  end
end
