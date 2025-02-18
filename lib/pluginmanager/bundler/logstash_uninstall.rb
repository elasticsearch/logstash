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

require "bootstrap/environment"
require "bundler"
require "bundler/definition"
require "bundler/dependency"
require "bundler/dsl"
require "bundler/injector"
require "pluginmanager/gemfile"

# This class cannot be in the logstash namespace, because of the way the DSL
# class interact with the other libraries
module Bundler
  class LogstashUninstall
    attr_reader :gemfile_path, :lockfile_path

    def initialize(gemfile_path, lockfile_path)
      @gemfile_path = gemfile_path
      @lockfile_path = lockfile_path
    end

    def uninstall!(gems_to_remove)
      gems_to_remove = Array(gems_to_remove)

      unsatisfied_dependency_mapping = Dsl.evaluate(gemfile_path, lockfile_path, {}).specs.each_with_object({}) do |spec, memo|
        next if gems_to_remove.include?(spec.name)
        deps = spec.runtime_dependencies.collect(&:name)
        deps.intersection(gems_to_remove).each do |missing_dependency|
          memo[missing_dependency] ||= []
          memo[missing_dependency] << spec.name
        end
      end
      if unsatisfied_dependency_mapping.any?
        unsatisfied_dependency_mapping.each { |gem_to_remove, gems_depending_on_removed| display_cant_remove_message(gem_to_remove, gems_depending_on_removed) }
        LogStash::PluginManager.ui.info("No plugins were removed.")
        return false
      end

      with_mutable_gemfile do |gemfile|
        gems_to_remove.each { |gem_name| gemfile.remove(gem_name) }

        builder = Dsl.new
        builder.eval_gemfile(::File.join(::File.dirname(gemfile_path), "gemfile to changes"), gemfile.generate)

        # build a definition, providing an intentionally-empty "unlock" mapping
        # to ensure that all gem versions remain locked
        definition = builder.to_definition(lockfile_path, {})

        # lock the definition and save our modified gemfile
        definition.lock(lockfile_path)
        gemfile.save

        gems_to_remove.each do |gem_name|
          LogStash::PluginManager.ui.info("Successfully removed #{gem_name}")
        end

        return true
      end
    end

    def display_cant_remove_message(gem_name, dependencies_from)
        message = <<~EOS
          Failed to remove \"#{gem_name}\" because the following plugins or libraries depend on it:
          * #{dependencies_from.join("\n* ")}
        EOS
        LogStash::PluginManager.ui.info(message)
    end

    def unfreeze_gemfile
      Bundler.definition.ensure_equivalent_gemfile_and_lockfile(true) if Bundler.settings[:frozen]

      Bundler.settings.temporary(:frozen => false) do
        yield
      end
    end

    ##
    # Yields a mutable gemfile backed by an open, writable file handle.
    # It is the responsibility of the caller to send `LogStash::Gemfile#save` to persist the result.
    # @yieldparam [LogStash::Gemfile]
    def with_mutable_gemfile
      unfreeze_gemfile do
        File.open(gemfile_path, 'r+') do |file|
          yield LogStash::Gemfile.new(file).load
        end
      end
    end

    def self.uninstall!(gem_names, options={})
      gemfile_path = options[:gemfile] || LogStash::Environment::GEMFILE
      lockfile_path = options[:lockfile] || LogStash::Environment::LOCKFILE
      LogstashUninstall.new(gemfile_path, lockfile_path).uninstall!(Array(gem_names))
    end
  end
end
