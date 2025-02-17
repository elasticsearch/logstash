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

Thread.abort_on_exception = false
Encoding.default_external = Encoding::UTF_8
$DEBUGLIST = (ENV["DEBUG"] || "").split(",")

require 'pathname'
LogStash::ROOT = Pathname.new(File.join(File.expand_path(File.dirname(__FILE__)), "..", "..", "..")).cleanpath.to_s
LogStash::XPACK_PATH = File.join(LogStash::ROOT, "x-pack")
LogStash::OSS = ENV["OSS"] == "true" || !File.exist?(LogStash::XPACK_PATH)

if !LogStash::OSS
  xpack_dir = File.join(LogStash::XPACK_PATH, "lib")
  unless $LOAD_PATH.include?(xpack_dir)
    $LOAD_PATH.unshift(xpack_dir)
  end
end

require "clamp"
require "logstash-core/logstash-core"
require "logstash/environment"
require "logstash/util/settings_helper"
require "logstash/util/jackson"

LogStash::Environment.load_locale!

require "logstash/agent"
require "logstash/config/defaults"
require "logstash/patches/clamp"
require "logstash/settings"
require "logstash/version"
require 'logstash/plugins'
require "logstash/bootstrap_check/default_config"
require 'logstash/deprecation_message'

java_import 'org.logstash.FileLockFactory'
java_import 'org.logstash.util.JavaVersion'

class LogStash::Runner < Clamp::StrictCommand
  include LogStash::Util::Loggable

  LogStash::Util::SettingsHelper.pre_process

  # Ordered list of check to run before starting logstash
  # theses checks can be changed by a plugin loaded into memory.
  DEFAULT_BOOTSTRAP_CHECKS = [
      LogStash::BootstrapCheck::DefaultConfig
  ]

  # Node Settings
  option ["-n", "--node.name"], "NAME",
    I18n.t("logstash.runner.flag.name"),
    :attribute_name => "node.name",
    :default => LogStash::SETTINGS.get_default("node.name")

  option ["--enable-local-plugin-development"], :flag,
         I18n.t("logstash.runner.flag.enable-local-plugin-development"),
         :attribute_name => "enable-local-plugin-development",
         :default => LogStash::SETTINGS.get_default("enable-local-plugin-development")

  # Config Settings
  option ["-f", "--path.config"], "CONFIG_PATH",
    I18n.t("logstash.runner.flag.config"),
    :attribute_name => "path.config"

  option ["-e", "--config.string"], "CONFIG_STRING",
    I18n.t("logstash.runner.flag.config-string",
      :default_input => LogStash::Config::Defaults.input,
      :default_output => LogStash::Config::Defaults.output),
    :default => LogStash::SETTINGS.get_default("config.string"),
    :attribute_name => "config.string"

  option ["--field-reference-escape-style"], "STYLE",
         I18n.t("logstash.runner.flag.field-reference-escape-style"),
         :default => LogStash::SETTINGS.get_default("config.field_reference.escape_style"),
         :attribute_name => "config.field_reference.escape_style"

  # Pipeline settings
  option ["--pipeline.id"], "ID",
    I18n.t("logstash.runner.flag.pipeline-id"),
    :attribute_name => "pipeline.id",
    :default => LogStash::SETTINGS.get_default("pipeline.id")

  option ["-w", "--pipeline.workers"], "COUNT",
    I18n.t("logstash.runner.flag.pipeline-workers"),
    :attribute_name => "pipeline.workers",
    :default => LogStash::SETTINGS.get_default("pipeline.workers")

  option "--pipeline.ordered", "ORDERED",
    I18n.t("logstash.runner.flag.pipeline-ordered"),
    :attribute_name => "pipeline.ordered",
    :default => LogStash::SETTINGS.get_default("pipeline.ordered")

  option ["--plugin-classloaders"], :flag,
         I18n.t("logstash.runner.flag.plugin-classloaders"),
         :attribute_name => "pipeline.plugin_classloaders",
         :default => LogStash::SETTINGS.get_default("pipeline.plugin_classloaders")

  option ["-b", "--pipeline.batch.size"], "SIZE",
    I18n.t("logstash.runner.flag.pipeline-batch-size"),
    :attribute_name => "pipeline.batch.size",
    :default => LogStash::SETTINGS.get_default("pipeline.batch.size")

  option ["-u", "--pipeline.batch.delay"], "DELAY_IN_MS",
    I18n.t("logstash.runner.flag.pipeline-batch-delay"),
    :attribute_name => "pipeline.batch.delay",
    :default => LogStash::SETTINGS.get_default("pipeline.batch.delay")

  option ["--pipeline.unsafe_shutdown"], :flag,
    I18n.t("logstash.runner.flag.unsafe_shutdown"),
    :attribute_name => "pipeline.unsafe_shutdown",
    :default => LogStash::SETTINGS.get_default("pipeline.unsafe_shutdown")

  option ["--pipeline.ecs_compatibility"], "STRING",
    I18n.t("logstash.runner.flag.ecs_compatibility"),
    :attribute_name => "pipeline.ecs_compatibility",
    :default => LogStash::SETTINGS.get_default('pipeline.ecs_compatibility')

  # Data Path Setting
  option ["--path.data"], "PATH",
    I18n.t("logstash.runner.flag.datapath"),
    :attribute_name => "path.data",
    :default => LogStash::SETTINGS.get_default("path.data")

  # Plugins Settings
  option ["-p", "--path.plugins"], "PATH",
    I18n.t("logstash.runner.flag.pluginpath"),
    :multivalued => true, :attribute_name => "path.plugins",
    :default => LogStash::SETTINGS.get_default("path.plugins")

  # Logging Settings
  option ["-l", "--path.logs"], "PATH",
    I18n.t("logstash.runner.flag.log"),
    :attribute_name => "path.logs",
    :default => LogStash::SETTINGS.get_default("path.logs")

  option "--log.level", "LEVEL", I18n.t("logstash.runner.flag.log_level"),
    :default => LogStash::SETTINGS.get_default("log.level"),
    :attribute_name => "log.level"

  option "--config.debug", :flag,
    I18n.t("logstash.runner.flag.config_debug"),
    :default => LogStash::SETTINGS.get_default("config.debug"),
    :attribute_name => "config.debug"

  # Other settings
  option ["-i", "--interactive"], "SHELL",
    I18n.t("logstash.runner.flag.rubyshell"),
    :attribute_name => "interactive"

  option ["-V", "--version"], :flag,
    I18n.t("logstash.runner.flag.version")

  option ["-t", "--config.test_and_exit"], :flag,
    I18n.t("logstash.runner.flag.configtest"),
    :attribute_name => "config.test_and_exit",
    :default => LogStash::SETTINGS.get_default("config.test_and_exit")

  option ["-r", "--config.reload.automatic"], :flag,
    I18n.t("logstash.runner.flag.auto_reload"),
    :attribute_name => "config.reload.automatic",
    :default => LogStash::SETTINGS.get_default("config.reload.automatic")

  option ["--config.reload.interval"], "RELOAD_INTERVAL",
    I18n.t("logstash.runner.flag.reload_interval"),
    :attribute_name => "config.reload.interval",
    :default => LogStash::SETTINGS.get_default("config.reload.interval")

  option ["--api.enabled"], "ENABLED",
    I18n.t("logstash.runner.flag.api_enabled"),
    :attribute_name => 'api.enabled',
    :default => LogStash::SETTINGS.get_default('api.enabled')

  option ["--api.http.host"], "HTTP_HOST",
    I18n.t("logstash.runner.flag.api_http_host"),
    :attribute_name => "api.http.host",
    :default => LogStash::SETTINGS.get_default("api.http.host")

  option ["--api.http.port"], "HTTP_PORT",
    I18n.t("logstash.runner.flag.api_http_port"),
    :attribute_name => "api.http.port",
    :default => LogStash::SETTINGS.get_default("api.http.port")

  option ["--log.format"], "FORMAT",
    I18n.t("logstash.runner.flag.log_format"),
    :attribute_name => "log.format",
    :default => LogStash::SETTINGS.get_default("log.format")

  option ["--log.format.json.fix_duplicate_message_fields"], "FORMAT_JSON_STRICT",
    I18n.t("logstash.runner.flag.log_format_json_fix_duplicate_message_fields"),
    :attribute_name => "log.format.json.fix_duplicate_message_fields",
    :default => LogStash::SETTINGS.get_default("log.format.json.fix_duplicate_message_fields")

  option ["--path.settings"], "SETTINGS_DIR",
    I18n.t("logstash.runner.flag.path_settings"),
    :attribute_name => "path.settings",
    :default => LogStash::SETTINGS.get_default("path.settings")

  ### DEPRECATED FLAGS ###
  deprecated_option ["--verbose"], :flag,
    I18n.t("logstash.runner.flag.verbose"),
    :new_flag => "log.level", :new_value => "info"

  deprecated_option ["--debug"], :flag,
    I18n.t("logstash.runner.flag.debug"),
    :new_flag => "log.level", :new_value => "debug"

  deprecated_option ["--quiet"], :flag,
    I18n.t("logstash.runner.flag.quiet"),
    :new_flag => "log.level", :new_value => "error"

  # We configure the registry and load any plugin that can register hooks
  # with logstash, this needs to be done before any operation.
  SYSTEM_SETTINGS = LogStash::SETTINGS.clone
  LogStash::PLUGIN_REGISTRY.setup!

  attr_reader :agent, :settings, :source_loader
  attr_accessor :bootstrap_checks

  def initialize(*args)
    @settings = LogStash::SETTINGS
    @bootstrap_checks = DEFAULT_BOOTSTRAP_CHECKS.dup

    # Default we check local sources: `-e`, `-f` and the logstash.yml options.
    @source_loader = LogStash::Config::SourceLoader.new(@settings)
    @source_loader.add_source(LogStash::Config::Source::Local.new(@settings))
    @source_loader.add_source(LogStash::Config::Source::MultiLocal.new(@settings))

    super(*args)
  end

  def run(args)
    return 1 unless LogStash::Util::SettingsHelper.from_yaml(args)
    super(*[args])
  end

  def execute
    LogStash::Util::SettingsHelper.post_process

    require "logstash/util"
    require "logstash/util/java_version"
    require "stud/task"

    running_as_superuser

    if log_configuration_contains_javascript_usage?
      logger.error("Logging configuration uses Script log appender or filter with Javascript, which is no longer supported.")
      return 1
    end

    if setting("config.debug") && !logger.debug?
      logger.warn("--config.debug was specified, but log.level was not set to \'debug\'! No config info will be logged.")
    end
    if setting("pipeline.buffer.type") != nil
      configure_pipeline_buffer_type
    end

    while (msg = LogStash::DeprecationMessage.instance.shift)
      deprecation_logger.deprecated msg
    end

    if JavaVersion::CURRENT < JavaVersion::JAVA_17
      deprecation_logger.deprecated I18n.t("logstash.runner.java.version_17_minimum",
                                           :java_home => java.lang.System.getProperty("java.home"))
    end

    logger.warn I18n.t("logstash.runner.java.home") if ENV["JAVA_HOME"]
    # Skip any validation and just return the version
    if version?
      show_version
      return 0
    end

    logger.info("Starting Logstash", "logstash.version" => LOGSTASH_VERSION, "jruby.version" => RUBY_DESCRIPTION)
    jvmArgs = ManagementFactory.getRuntimeMXBean().getInputArguments()
    logger.info "JVM bootstrap flags: #{jvmArgs}"


    # Verify the Jackson defaults
    LogStash::Util::Jackson.verify_jackson_overrides

    @dispatcher = LogStash::EventDispatcher.new(self)
    LogStash::PLUGIN_REGISTRY.hooks.register_emitter(self.class, @dispatcher)

    validate_settings! or return 1
    @dispatcher.fire(:before_bootstrap_checks)

    field_reference_escape_style_setting = settings.get_setting('config.field_reference.escape_style')
    if field_reference_escape_style_setting.set?
      logger.warn(I18n.t("logstash.settings.technical_preview.set", :canonical_name => field_reference_escape_style_setting.name))
    end
    field_reference_escape_style = field_reference_escape_style_setting.value
    logger.debug("Setting global FieldReference escape style: #{field_reference_escape_style}")
    org.logstash.FieldReference::set_escape_style(field_reference_escape_style)

    return start_shell(setting("interactive"), binding) if setting("interactive")

    begin
      @bootstrap_checks.each { |bootstrap| bootstrap.check(@settings) }
    rescue LogStash::BootstrapCheckError => e
      signal_usage_error(e.message)
      return 1
    end
    @dispatcher.fire(:after_bootstrap_checks)

    LogStash::Util::set_thread_name(self.class.name)

    LogStash::ShutdownWatcher.unsafe_shutdown = setting("pipeline.unsafe_shutdown")

    configure_plugin_paths(setting("path.plugins"))

    @settings.format_settings.each {|line| logger.debug(line) }

    # Check for absence of any configuration
    # not bulletproof because we don't know yet if there
    # are no pipelines from pipelines.yml
    sources_without_conflict = []
    unmatched_sources_conflict_messages = []
    @source_loader.sources do |source|
      if source.config_conflict?
        if source.conflict_messages.any?
          unmatched_sources_conflict_messages << source.conflict_messages.join(", ")
        end
      else
        sources_without_conflict << source
      end
    end
    if unmatched_sources_conflict_messages.any?
      # i18n should be done at the sources side
      signal_usage_error(unmatched_sources_conflict_messages.join(" "))
      return 1
    elsif sources_without_conflict.empty?
      signal_usage_error(I18n.t("logstash.runner.missing-configuration"))
      return 1
    end

    if setting("config.test_and_exit")
      begin
        results = @source_loader.fetch

        # TODO(ph): make it better for multiple pipeline
        if results.success?
          results.response.each { |pipeline_config| LogStash::JavaPipeline.new(pipeline_config) }
          puts "Configuration OK"
          logger.info "Using config.test_and_exit mode. Config Validation Result: OK. Exiting Logstash"
        else
          raise "Could not load the configuration file"
        end
        return 0
      rescue => e
        logger.fatal I18n.t("logstash.runner.invalid-configuration", :error => e.message)
        return 1
      end
    end

    # lock path.data before starting the agent
    @data_path_lock = FileLockFactory.obtainLock(java.nio.file.Paths.get(setting("path.data")).to_absolute_path, ".lock")

    @dispatcher.fire(:before_agent)
    @agent = create_agent(@settings, @source_loader)
    @dispatcher.fire(:after_agent)

    # enable sigint/sigterm before starting the agent
    # to properly handle a stalled agent
    sigint_id = trap_sigint()
    sigterm_id = trap_sigterm()

    @agent_task = Stud::Task.new { @agent.execute }

    # no point in enabling config reloading before the agent starts
    # also windows doesn't have SIGHUP. we can skip it
    sighup_id = LogStash::Environment.windows? ? nil : trap_sighup()

    agent_return = @agent_task.wait

    @agent.shutdown

    logger.info("Logstash shut down.")

    # flush any outstanding log messages during shutdown
    org.apache.logging.log4j.LogManager.shutdown

    agent_return
  rescue org.logstash.LockException => e
    logger.fatal(I18n.t("logstash.runner.locked-data-path", :path => setting("path.data")))
    return 1
  rescue Clamp::UsageError => e
    $stderr.puts "ERROR: #{e.message}"
    show_short_help
    return 1
  rescue => e
    # if logger itself is not initialized
    if LogStash::Logging::Logger.get_logging_context.nil?
      $stderr.puts "#{I18n.t("oops")} :error => #{e}, :backtrace => #{e.backtrace}"
    else
      logger.fatal(I18n.t("oops"), :error => e, :backtrace => e.backtrace)
    end
    return 1
  ensure
    Stud::untrap("INT", sigint_id) unless sigint_id.nil?
    Stud::untrap("TERM", sigterm_id) unless sigterm_id.nil?
    Stud::untrap("HUP", sighup_id) unless sighup_id.nil?
    FileLockFactory.releaseLock(@data_path_lock) if @data_path_lock
    @log_fd.close if @log_fd
  end # def self.main

  def running_as_superuser
    return if LogStash::Environment.windows? # windows euid always returns 0, skip checking

    if Process.euid() == 0
      if setting("allow_superuser")
        logger.warn("NOTICE: Allowing Logstash to run as superuser is heavily discouraged as it poses a security risk. " +
                      "It is strongly recommended to set 'allow_superuser' to false.")
      else
        raise(RuntimeError, "Logstash cannot be run as superuser.")
      end
    end
  end

  def log_configuration_contains_javascript_usage?
     context = LoggerContext.getContext(false)
     config = context.configuration
     config_file = config.configuration_source.file
     # no config file so nothing to check
     return false if config_file.nil?

     logger.info("Log4j configuration path used is: #{config_file.path}")
     log_config = File.open(config_file.absolute_path).read
     (log_config =~ /^[^#]+script\.language\s*=\s*JavaScript/) != nil
  end

  def validate_settings!
    @settings.validate_all
    true
  rescue => e
    $stderr.puts(I18n.t("logstash.runner.invalid-settings", :error => e.message))
    return false
  end

  def show_version
    show_version_logstash

    if logger.info?
      show_version_ruby
      show_version_java
      show_gems if logger.debug?
    end
  end # def show_version

  def show_version_logstash
    puts "logstash #{LOGSTASH_VERSION}"
  end # def show_version_logstash

  def show_version_ruby
    puts RUBY_DESCRIPTION
  end # def show_version_ruby

  def show_version_java
    properties = java.lang.System.getProperties
    puts "java #{properties["java.version"]} (#{properties["java.vendor"]})"
    puts "jvm #{properties["java.vm.name"]} / #{properties["java.vm.version"]}"
  end # def show_version_java

  def show_gems
    require "rubygems"
    Gem::Specification.each do |spec|
      puts "gem #{spec.name} #{spec.version}"
    end
  end # def show_gems

  # add the given paths for ungemified/bare plugins lookups
  # @param paths [String, Array<String>] plugins path string or list of path strings to add
  def configure_plugin_paths(paths)
    Array(paths).each do |path|
      fail(I18n.t("logstash.runner.configuration.plugin_path_missing", :path => path)) unless File.directory?(path)
      LogStash::Environment.add_plugin_path(path)
    end
  end

  def create_agent(*args)
    LogStash::Agent.new(*args)
  end

  # Emit a failure message and abort.
  def fail(message)
    signal_usage_error(message)
  end # def fail

  def show_short_help
    puts I18n.t("logstash.runner.short-help")
  end

  def start_shell(shell, start_binding)
    case shell
    when "pry"
      require 'pry'
      start_binding.pry
    when "irb"
      require 'irb'
      ARGV.clear
      # TODO: set binding to this instance of Runner
      # currently bugged as per https://github.com/jruby/jruby/issues/384
      IRB.start(__FILE__)
    else
      fail(I18n.t("logstash.runner.invalid-shell"))
    end
  end

  def trap_sighup
    Stud::trap("HUP") do
      logger.warn(I18n.t("logstash.agent.sighup"))
      @agent.converge_state_and_update
    end
  end

  def trap_sigterm
    Stud::trap("TERM") do
      logger.warn(I18n.t("logstash.agent.sigterm"))
      @agent_task.stop!
    end
  end

  def trap_sigint
    Stud::trap("INT") do
      if @interrupted_once
        logger.fatal(I18n.t("logstash.agent.forced_sigint"))
        # calling just Kernel.exit only raises SystemExit exception
        # and doesn't guarantee the process will terminate
        # We must call Kernel.exit! so java.lang.System.exit is called
        exit!(1)
      else
        logger.warn(I18n.t("logstash.agent.sigint"))
        Thread.new(logger) {|lg| sleep 5; lg.warn(I18n.t("logstash.agent.slow_shutdown")) }
        @interrupted_once = true
        @agent_task.stop!
      end
    end
  end

  def setting(key)
    @settings.get_value(key)
  end

  def configure_pipeline_buffer_type
    # if user hasn't explicitly set Netty's interested property
    if java.lang.System.getProperty("io.netty.noPreferDirect") == nil
      if setting("pipeline.buffer.type") == "heap"
        # set Netty's Java properties to prefer heap memory allocation
        java.lang.System.setProperty("io.netty.noPreferDirect", "true")
      else
        # set Netty's Java properties to prefer direct memory allocation
        java.lang.System.setProperty("io.netty.noPreferDirect", "false")
      end
    else
      logger.warn("Ignoring 'pipeline.buffer.type' since the 'io.netty.noPreferDirect' Java property has already been set (check LS_JAVA_OPTS or jvm.options file.")
    end
  end

end
