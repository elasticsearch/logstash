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

# work around https://github.com/jruby/jruby/issues/8579
require_relative './patches/jar_dependencies'

module LogStash
  module Bundler
    extend self

    def patch!
      # Patch to prevent Bundler to save a .bundle/config file in the root
      # of the application
      ::Bundler::Settings.module_exec do
        def set_local(key, value)
          set_key(key, value, @local_config, nil)
        end
      end

      # In recent versions (currently 1.17.3) Bundler calls reset_paths! early during
      # Bundler::CLI.start (https://github.com/bundler/bundler/blob/v1.17.3/lib/bundler/cli.rb#L39)
      # This breaks our setting up of gemfile and bundle paths, the without group setting etc
      # We need to tone down this very aggressive resetter (https://github.com/bundler/bundler/blob/v1.17.3/lib/bundler.rb#L487-L500)
      # So we reimplement it here to only nullify the definition object, so that it can be computed
      # again if necessary with all the configuration in place.
      ::Bundler.module_exec do
        def self.reset_paths!
          @definition = nil
        end
      end

      # This patch makes rubygems fetch directly from the remote servers
      # the dependencies he need and might not have downloaded in a local
      # repository. This basically enabled the offline feature to work as
      # we remove the gems from the vendor directory before packaging.
      ::Bundler::Source::Rubygems.module_exec do
        def cached_built_in_gem(spec, local: false)
          remote_spec = remote_specs.search(spec).first
          if remote_spec
            cached_path = fetch_gem(remote_spec)
            spec.remote = remote_spec.remote
          else
            ::Bundler.ui.warn "#{spec.full_name} is built in to Ruby, and can't be cached because your Gemfile doesn't have any sources that contain it."
          end
          cached_path
        end

        def cache(spec, custom_path = nil)
          #cached_path = Bundler.settings[:cache_all_platforms] ? fetch_gem_if_possible(spec) : cached_gem(spec)
          cached_path = cached_built_in_gem(spec)
          raise GemNotFound, "Missing gem file '#{spec.file_name}'." unless cached_path
          return if ::File.dirname(cached_path) == ::Bundler.app_cache.to_s
          ::Bundler.ui.info "  * #{File.basename(cached_path)}"
          ::FileUtils.cp(cached_path, ::Bundler.app_cache(custom_path))
        rescue Errno::EACCES => e
          ::Bundler.ui.debug(e)
          raise InstallError, e.message
        end
      end
    end

    # prepare bundler's environment variables, but do not invoke ::Bundler::setup
    def prepare(options = {})
      options = {:without => [:development]}.merge(options)
      options[:without] = Array(options[:without])

      ::Gem.clear_paths
      ENV['GEM_HOME'] = ENV['GEM_PATH'] = Environment.logstash_gem_home
      ::Gem.paths = ENV

      # set BUNDLE_GEMFILE ENV before requiring bundler to avoid bundler recurse and load unrelated Gemfile(s)
      ENV["BUNDLE_GEMFILE"] = Environment::GEMFILE_PATH

      require "bundler"
      LogStash::Bundler.patch!

      ::Bundler.settings.set_local(:path, Environment::BUNDLE_DIR)
      ::Bundler.settings.set_local(:without, options[:without])
      # in the context of Bundler.setup it looks like this is useless here because Gemfile path can only be specified using
      # the ENV, see https://github.com/bundler/bundler/blob/v1.8.3/lib/bundler/shared_helpers.rb#L103
      ::Bundler.settings.set_local(:gemfile, Environment::GEMFILE_PATH)
      ::Bundler.settings.set_local(:frozen, true) unless options[:allow_gemfile_changes]
      ::Bundler.reset!
    end

    # After +Bundler.setup+ call, all +load+ or +require+ of the gems would be allowed only if they are part of
    # the Gemfile or Ruby's standard library
    # To install a new plugin which is not part of Gemfile, DO NOT call setup!
    def setup!(options = {})
      prepare(options)
      ::Bundler.setup
    end

    # execute bundle install and capture any $stdout output. any raised exception in the process will be trapped
    # and returned. logs errors to $stdout.
    # @param [Hash] options invoke options with default values, :max_tries => 10, :clean => false, :install => false, :update => false
    # @option options [Boolean] :max_tries The number of times bundler is going to try the installation before failing (default: 10)
    # @option options [Boolean] :clean It cleans the unused gems (default: false)
    # @option options [Boolean] :install Run the installation of a set of gems defined in a Gemfile (default: false)
    # @option options [Boolean, String, Array] :update Update the current environment, must be either false or a String or an Array of String (default: false)
    # @option options [Boolean] :local Do not attempt to fetch gems remotely and use the gem cache instead (default: false)
    # @option options [Boolean] :package Locks and then caches all dependencies to be reused later on (default: false)
    # @option options [Boolean] :all It packages dependencies defined with :git or :path (default: false)
    # @option options [Array] :without  Exclude gems that are part of the specified named group (default: [:development])
    # @return [String, Exception] the installation captured output and any raised exception or nil if none
    def invoke!(options = {})
      options = {:max_tries => 10, :clean => false, :install => false, :update => false, :local => false,
                 :jobs => 12, :all => false, :package => false, :without => [:development]}.merge(options)
      options[:without] = Array(options[:without])
      options[:update] = Array(options[:update]) if options[:update]
      ::Gem.clear_paths
      ENV['GEM_HOME'] = ENV['GEM_PATH'] = LogStash::Environment.logstash_gem_home
      ::Gem.paths = ENV
      # set BUNDLE_GEMFILE ENV before requiring bundler to avoid bundler recurse and load unrelated Gemfile(s).
      # in the context of calling Bundler::CLI this is not really required since Bundler::CLI will look at
      # Bundler.settings[:gemfile] unlike Bundler.setup. For the sake of consistency and defensive/future proofing, let's keep it here.
      ENV["BUNDLE_GEMFILE"] = LogStash::Environment::GEMFILE_PATH

      require "bundler"
      require "bundler/cli"
      require_relative './patches/gems'

      require "fileutils"
      # create Gemfile from template iff it does not exist
      unless ::File.exist?(Environment::GEMFILE_PATH)
        FileUtils.copy(
          ::File.join(Environment::LOGSTASH_HOME, "Gemfile.template"), Environment::GEMFILE_PATH
        )
      end
      # create Gemfile.jruby-1.9.lock from template iff a template exists it itself does not exist
      lock_template = ::File.join(ENV["LOGSTASH_HOME"], "Gemfile.jruby-3.1.lock.release")
      if ::File.exist?(lock_template) && !::File.exist?(Environment::LOCKFILE)
        FileUtils.copy(lock_template, Environment::LOCKFILE)
      end

      LogStash::Bundler.patch!

      # force Rubygems sources to our Gemfile sources
      ::Gem.sources = ::Gem::SourceList.from(options[:rubygems_source]) if options[:rubygems_source]

      ::Bundler.settings.set_local(:path, LogStash::Environment::BUNDLE_DIR)
      ::Bundler.settings.set_local(:gemfile, LogStash::Environment::GEMFILE_PATH)
      ::Bundler.settings.set_local(:without, options[:without])
      ::Bundler.settings.set_local(:force, options[:force])

      # This env setting avoids the warning given when bundler is run as root, as is required
      # to update plugins when logstash is run as a service
      # Note: Using `ENV`s here because ::Bundler.settings.set_local or `bundle config`
      # is not being respected with `Bundler::CLI.start`?
      # (set_global *does*, but that seems too drastic a change)
      with_env({"BUNDLE_PATH" => LogStash::Environment::BUNDLE_DIR,
                "BUNDLE_GEMFILE" => LogStash::Environment::GEMFILE_PATH,
                "BUNDLE_SILENCE_ROOT_WARNING" => "true",
                "BUNDLE_WITHOUT" => options[:without].join(":")}) do
        if !debug?
          # Will deal with transient network errors
          execute_bundler_with_retry(options)
        else
          options[:verbose] = true
          execute_bundler(options)
          ""
        end
      end
    end

    def execute_bundler_with_retry(options)
      try = 0
      # capture_stdout also traps any raised exception and pass them back as the function return [output, exception]
      output, exception = capture_stdout do
        loop do
          begin
            execute_bundler(options)
            break
          rescue ::Bundler::SolveFailure => e
            $stderr.puts("Plugin version conflict, aborting")
            raise(e)
          rescue ::Bundler::GemNotFound => e
            $stderr.puts("Plugin not found, aborting")
            raise(e)
          rescue => e
            if try >= options[:max_tries]
              $stderr.puts("Too many retries, aborting, caused by #{e.class}")
              $stderr.puts(e.message) if ENV["DEBUG"]
              raise(e)
            end

            try += 1
            $stderr.puts("Error #{e.class}, retrying #{try}/#{options[:max_tries]}")
            $stderr.puts(e.message)
            sleep(0.5)
          end
        end
      end
      raise exception if exception

      return output
    end

    def execute_bundler(options)
      ::Bundler.reset!
      ::Bundler::CLI.start(bundler_arguments(options))
    end

    def specific_platforms(platforms = ::Gem.platforms)
      platforms.find_all {|plat| plat.is_a?(::Gem::Platform) && plat.os == 'java' && !plat.cpu.nil?}
    end

    def genericize_platform
      output = LogStash::Bundler.invoke!({:add_platform => 'java'})
      specific_platforms.each do |platform|
        output << LogStash::Bundler.invoke!({:remove_platform => platform})
      end
      output
    end

    def debug?
      ENV["DEBUG"]
    end

    # @param plugin_names [Array] logstash plugin names that are going to update
    # @return [Array] gem names that plugins depend on, including logstash plugins
    def expand_logstash_mixin_dependencies(plugin_names); require 'set'
      plugin_names = Array(plugin_names) if plugin_names.is_a?(String)

      # get gem names in Gemfile.lock. If file doesn't exist, it will be generated
      lockfile_gems = ::Bundler::definition.specs.to_a.map { |stub_spec| stub_spec.name }.to_set

      # get the array of dependencies which are eligible to update. Bundler unlock these gems in update process
      # exclude the gems which are not in lock file. They should not be part of unlock gems.
      # The core libs, logstash-core logstash-core-plugin-api, are not expected to update when user do plugins update
      # constraining the transitive dependency updates to only those Logstash maintain
      unlock_libs = plugin_names.flat_map { |plugin_name| fetch_plugin_dependencies(plugin_name) }
                                .uniq
                                .select { |lib_name| lockfile_gems.include?(lib_name) }
                                .select { |lib_name| lib_name.start_with?("logstash-mixin-") }

      unlock_libs + plugin_names
    end

    # get all dependencies of a single plugin, considering all versions >= current
    # @param plugin_name [String] logstash plugin name
    # @return [Array] gem names that plugin depends on
    def fetch_plugin_dependencies(plugin_name)
      old_spec = ::Gem::Specification.find_all_by_name(plugin_name).last
      require_version = old_spec ? ">= #{old_spec.version}" : nil
      dep = ::Gem::Dependency.new(plugin_name, require_version)
      new_specs, errors = ::Gem::SpecFetcher.fetcher.spec_for_dependency(dep)

      raise(errors.first.error) if errors.length > 0

      new_specs.map { |spec, source| spec }
               .flat_map(&:dependencies)
               .select {|spec| spec.type == :runtime }
               .map(&:name)
               .uniq
    end

    # build Bundler::CLI.start arguments array from the given options hash
    # @param option [Hash] the invoke! options hash
    # @return [Array<String>] Bundler::CLI.start string arguments array
    def bundler_arguments(options = {})
      arguments = []
      if options[:install]
        arguments << "install"
        arguments << "--clean" if options[:clean]
        if options[:local]
          arguments << "--local"
          arguments << "--no-prune" # From bundler docs: Don't remove stale gems from the cache.
        end
        if options[:force]
          arguments << "--redownload"
        end
      elsif options[:update]
        arguments << "update"
        arguments << expand_logstash_mixin_dependencies(options[:update])
        arguments << "--#{options[:level] || 'minor'}"
        arguments << "--local" if options[:local]
        arguments << "--conservative" if options[:conservative]
      elsif options[:clean]
        arguments << "clean"
      elsif options[:package]
        arguments << "package"
        arguments << "--all" if options[:all]
      elsif options[:add_platform]
        arguments << "lock"
        arguments << "--add_platform"
        arguments << options[:add_platform]
      elsif options[:remove_platform]
        arguments << "lock"
        arguments << "--remove_platform"
        arguments << options[:remove_platform]
      end

      arguments << "--verbose" if options[:verbose]
      arguments.flatten
    end

    def with_env(modifications)
      backup_env = ENV.to_hash
      ENV.replace(backup_env.merge(modifications))

      yield
    ensure
      ENV.replace(backup_env)
    end

    # capture any $stdout from the passed block. also trap any exception in that block, in which case the trapped exception will be returned
    # @param [Proc] the code block to execute
    # @return [String, Exception] the captured $stdout string and any trapped exception or nil if none
    def capture_stdout(&block); require 'stringio'
      old_stdout = $stdout
      $stdout = StringIO.new("", "w")
      begin
        block.call
      rescue => e
        return [$stdout.string, e]
      end

      [$stdout.string, nil]
    ensure
      $stdout = old_stdout
    end
  end
end
