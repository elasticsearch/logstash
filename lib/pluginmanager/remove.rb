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

require "pluginmanager/bundler/logstash_uninstall"
require "pluginmanager/x_pack_interceptor.rb"
require "pluginmanager/command"

class LogStash::PluginManager::Remove < LogStash::PluginManager::Command
  parameter "PLUGIN ...", "plugin name(s)"

  def execute
    signal_error("One or more plugins must be specified") if plugin_list.empty?
    signal_error("File #{LogStash::Environment::GEMFILE_PATH} does not exist or is not writable, aborting") unless File.writable?(LogStash::Environment::GEMFILE_PATH)

    LogStash::Bundler.prepare({:without => [:build, :development]})

    plugin_list.each do |plugin|
      if LogStash::PluginManager::ALIASES.has_key?(plugin)
        unless LogStash::PluginManager.installed_plugin?(plugin, gemfile)
          aliased_plugin = LogStash::PluginManager::ALIASES[plugin]
          puts "Cannot remove the alias #{plugin}, which is an alias for #{aliased_plugin}; if you wish to remove it, you must remove the aliased plugin instead."
          return
        end
      end

      # If a user is attempting to uninstall X-Pack, present helpful output to guide
      # them toward the OSS-only distribution of Logstash
      LogStash::PluginManager::XPackInterceptor::Remove.intercept!(plugin)

      # if the plugin is provided by an integration plugin. abort.
      if integration_plugin = LogStash::PluginManager.which_integration_plugin_provides(plugin, gemfile)
        signal_error("The plugin `#{plugin}` is provided by '#{integration_plugin.name}' so it can't be removed individually")
      end

      not_installed_message = "The plugin `#{plugin}` has not been previously installed"
      plugin_gem_spec = LogStash::PluginManager.find_plugins_gem_specs(plugin).any?
      if plugin_gem_spec
        # make sure this is an installed plugin and present in Gemfile.
        # it is not possible to uninstall a dependency not listed in the Gemfile, for example a dependent codec
        signal_error(not_installed_message) unless LogStash::PluginManager.installed_plugin?(plugin, gemfile)
      else
        # locally installed plugins are not recoginized by ::Gem::Specification
        # we may ::Bundler.setup to reload but it resets all dependencies so we get error message for future bundler operations
        # error message: `Bundler::GemNotFound: Could not find rubocop-1.60.2... in locally installed gems`
        # instead we make sure Gemfile has a definition and ::Gem::Specification recognizes local gem
        signal_error(not_installed_message) unless !!gemfile.find(plugin)

        local_gem = gemfile.locally_installed_gems.detect { |local_gem| local_gem.name == plugin }
        signal_error(not_installed_message) unless local_gem
      end
    end

    exit(1) unless ::Bundler::LogstashUninstall.uninstall!(plugin_list)
    LogStash::Bundler.genericize_platform
    remove_unused_locally_installed_gems!
  rescue => exception
    report_exception("Operation aborted, cannot remove plugin", exception)
  end
end
