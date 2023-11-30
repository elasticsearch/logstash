# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

require "logstash/devutils/rspec/spec_helper"
require_relative "support/matchers"
require_relative "support/helpers"
require "monitoring/inputs/metrics"
require 'simplecov'
require 'simplecov-json'

if ENV['TEST_DEBUG']
  java.lang.System.setProperty("ls.log.level", "debug")
end

SimpleCov.formatters = SimpleCov::Formatter::MultiFormatter.new([
  SimpleCov::Formatter::HTMLFormatter,
  SimpleCov::Formatter::JSONFormatter
])

SimpleCov.start
