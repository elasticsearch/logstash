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

require_relative "default_plugins"
require 'rubygems'

namespace "plugin" do
  def install_plugins(*args)
    require_relative "../lib/pluginmanager/main"
    LogStash::PluginManager::Main.run("bin/logstash-plugin", ["install"] + args)
  end

  def remove_plugin(plugin, *more_plugins)
    require_relative "../lib/pluginmanager/main"
    LogStash::PluginManager::Main.run("bin/logstash-plugin", ["remove", plugin] + more_plugins)
  end

  task "install-base" => "bootstrap" do
    puts("[plugin:install-base] Installing base dependencies")
    install_plugins("--development",  "--preserve")
    task.reenable # Allow this task to be run again
  end

  def remove_lockfile
    if ::File.exist?(LogStash::Environment::LOCKFILE)
      ::File.delete(LogStash::Environment::LOCKFILE)
    end
  end

  task "install-development-dependencies" => "bootstrap" do
    puts("[plugin:install-development-dependencies] Installing development dependencies")
    install_plugins("--development",  "--preserve")
    install_plugins("--preserve", *LogStash::RakeLib::CORE_SPECS_PLUGINS)

    task.reenable # Allow this task to be run again
  end

  task "install", :name do |task, args|
    name = args[:name]
    puts("[plugin:install] Installing plugin: #{name}")
    install_plugins("--no-verify", "--preserve", name)

    task.reenable # Allow this task to be run again
  end # task "install"

  task "install-default" => "bootstrap" do
    puts("[plugin:install-default] Installing default plugins")

    remove_lockfile # because we want to use the release lockfile
    install_plugins("--no-verify", "--preserve", *LogStash::RakeLib::DEFAULT_PLUGINS)

    task.reenable # Allow this task to be run again
  end

  task "remove-non-oss-plugins" do |task, _|
    puts("[plugin:remove-non-oss-plugins] Removing non-OSS plugins")

    LogStash::RakeLib::OSS_EXCLUDED_PLUGINS.each do |plugin|
      remove_plugin(plugin)
      # gem folder and spec file still stay after removing the plugin
      FileUtils.rm_r(Dir.glob("#{LogStash::Environment::BUNDLE_DIR}/**/gems/#{plugin}*"))
      FileUtils.rm_r(Dir.glob("#{LogStash::Environment::BUNDLE_DIR}/**/specifications/#{plugin}*.gemspec"))
    end
    task.reenable # Allow this task to be run again
  end

  task "clean-local-core-gem", [:name, :path] do |task, args|
    name = args[:name]
    path = args[:path]

    Dir[File.join(path, "#{name}*.gem")].each do |gem|
      puts("[plugin:clean-local-core-gem] Cleaning #{gem}")
      rm(gem)
    end

    task.reenable # Allow this task to be run again
  end

  task "build-local-core-gem", [:name, :path] => ["build/gems"]  do |task, args|
    name = args[:name]
    path = args[:path]

    Rake::Task["plugin:clean-local-core-gem"].invoke(name, path)

    puts("[plugin:build-local-core-gem] Building #{File.join(path, name)}.gemspec")

    gem_path = nil
    Dir.chdir(path) do
      spec = Gem::Specification.load("#{name}.gemspec")
      gem_path = Gem::Package.build(spec)
    end
    FileUtils.cp(File.join(path, gem_path), "build/gems/")

    task.reenable # Allow this task to be run again
  end

  task "install-local-core-gem", [:name, :path] do |task, args|
    name = args[:name]
    path = args[:path]

    Rake::Task["plugin:build-local-core-gem"].invoke(name, path)

    gems = Dir[File.join(path, "#{name}*.gem")]
    abort("ERROR: #{name} gem not found in #{path}") if gems.size != 1
    puts("[plugin:install-local-core-gem] Installing #{gems.first}")
    install_plugins("--no-verify", gems.first)

    task.reenable # Allow this task to be run again
  end
end # namespace "plugin"
