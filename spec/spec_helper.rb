# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

require "logstash/devutils/rspec/spec_helper"

require "flores/rspec"
require "flores/random"
require "pathname"
require "stud/task"
require "support/resource_dsl_methods"
require "support/mocks_classes"
require "support/helpers"
require "support/shared_contexts"
require "support/shared_examples"
require 'rspec/expectations'
require "logstash/settings"
require 'rack/test'
require 'rspec'
require "json"
require 'logstash/runner'

# Code coverage setup
if ENV['COVERAGE']
  require 'simplecov'
  require 'simplecov-json'

  SimpleCov.formatter = SimpleCov::Formatter::JSONFormatter

  SimpleCov.start do
    add_filter 'spec/'
    add_filter 'vendor/'
  end
end

class JSONIOThingy < IO
  def initialize; end
  def flush; end

  def puts(payload)
    # Ensure that all log payloads are valid json.
    LogStash::Json.load(payload)
  end
end

# Refactor the suite to https://github.com/elastic/logstash/issues/7148
RSpec::Expectations.configuration.on_potential_false_positives = :nothing

RSpec.configure do |c|
  Flores::RSpec.configure(c)
  c.include LogStashHelper
  c.extend LogStashHelper

  if ENV['COVERAGE']
    c.after(:suite) do
      SimpleCov.result.format!
    end
  end

  # Some tests mess with LogStash::SETTINGS, and data on the filesystem can leak state
  # from one spec to another; run each spec with its own temporary data directory for `path.data`
  c.around(:each) do |example|
    Dir.mktmpdir do |temp_directory|
      # Some tests mess with the settings. This ensures one test cannot pollute another
      LogStash::SETTINGS.reset

      LogStash::SETTINGS.set("queue.type", "memory")
      LogStash::SETTINGS.set("path.data", temp_directory)

      LogStash::Util.set_thread_name("RSPEC Example #{example.full_description} (from: `#{example.location}`)") do
        example.run
      end
    end
  end
end

def installed_plugins
  Gem::Specification.find_all.select { |spec| spec.metadata["logstash_plugin"] }.map { |plugin| plugin.name }
end


def setup_logger_spy
  java_import org.apache.logging.log4j.core.config.builder.api.ConfigurationBuilderFactory
  java_import org.apache.logging.log4j.Level
  config_builder = ConfigurationBuilderFactory.newConfigurationBuilder
  configure_log_spy = config_builder
                        .add(
                          config_builder
                            .newAppender("LOG_SPY", "List")
                            .add(config_builder.newLayout("PatternLayout").addAttribute("pattern", "%-5p [%t]: %m%n"))
                        )
                        .add(
                          config_builder
                            .newRootLogger(Level::INFO)
                            .add(config_builder.newAppenderRef("LOG_SPY")))
                        .build(false)

  java_import org.apache.logging.log4j.core.config.Configurator
  java_import org.apache.logging.log4j.core.config.Configuration

  java_import org.apache.logging.log4j.LogManager
  java_import org.apache.logging.log4j.core.impl.Log4jContextFactory
  # This is done because the LoggerExt calls setFactory LogstashLoggerContextFactory implements
  # org.apache.logging.log4j.spi.LoggerContextFactory and doesn't extend org.apache.logging.log4j.core.impl.Log4jContextFactory
  # which is the class expected by the following Configurator to use the programmatic configuration.
  LogManager.setFactory(Log4jContextFactory.new)
  log_ctx = Configurator.java_send(:initialize, [Configuration], configure_log_spy)
  expect(log_ctx).not_to be nil
  log_ctx.reconfigure(configure_log_spy) # force the programmatic configuration, without this it's not used

  return log_ctx
end

def retrieve_logger_spy(log_ctx)
  log_ctx.getConfiguration().getAppender("LOG_SPY")
end
