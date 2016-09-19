# encoding: utf-8
require "logstash/namespace"
require "logstash/logging/slow_logger/freq_items"

# This module contains necessary classes to handle slow log
# operations.
module LogStash; module Logging

  # Slow log null logger, this logger does
  # nothing when used.
  class NullLogger
    def log(event, threshold, time, data={})
    end
    alias_method :warn, :log
  end

  # Generic slow logger, this class is responsible of
  # reporting to the specific logger and holding an
  # aggregated view of it's reported events.
  class SlowLogger

    attr_reader :logger, :freq_items, :settings

    def initialize(name="loggers.slow", settings=LogStash::SETTINGS, params={})
      @logger     = LogStash::Logging::Logger.new(name)
      @freq_items = LogStash::Logging::Util::FreqItems.new
      @settings   = settings
    end

    def log(event, threshold, took_in_seconds, data={})
      max_time = setting(threshold).to_i
      return if max_time == 0 || took_in_seconds <= max_time

      data[:event] = event
      data[:threshold] = threshold
      data[:took_in_seconds] = took_in_seconds
      message = "Threshold #{threshold} has been overcome with #{took_in_seconds}"

      freq_items.add(threshold, took_in_seconds)
      logger.warn(message, data)
    end
    alias_method :warn, :log

    def logger=(logger)
      @logger = logger
    end

    private

    def setting(key)
      @settings.get_value(key) rescue nil
    end

  end

end; end
