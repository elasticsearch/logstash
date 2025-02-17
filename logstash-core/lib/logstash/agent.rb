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

require "logstash/environment"
require "logstash/config/cpu_core_strategy"
require "logstash/instrument/collector"
require "logstash/instrument/periodic_pollers"
require "logstash/webserver"
require "logstash/config/source_loader"
require "logstash/config/pipeline_config"
require "logstash/pipeline_action"
require "logstash/state_resolver"
require "logstash/pipelines_registry"
require "logstash/persisted_queue_config_validator"
require "logstash/pipeline_resource_usage_validator"
require "stud/trap"
require "uri"
require "socket"
require "securerandom"

LogStash::Environment.load_locale!

class LogStash::Agent
  include LogStash::Util::Loggable
  STARTED_AT = Time.now.freeze

  attr_reader :metric, :name, :settings, :dispatcher, :ephemeral_id, :pipeline_bus
  attr_accessor :logger

  attr_reader :health_observer

  # initialize method for LogStash::Agent
  # @param params [Hash] potential parameters are:
  #   :name [String] - identifier for the agent
  #   :auto_reload [Boolean] - enable reloading of pipelines
  #   :reload_interval [Integer] - reload pipelines every X seconds
  def initialize(settings = LogStash::SETTINGS, source_loader = nil)
    @logger = self.class.logger
    @settings = settings
    @auto_reload = setting("config.reload.automatic")
    @ephemeral_id = SecureRandom.uuid

    java_import("org.logstash.health.HealthObserver")
    @health_observer ||= HealthObserver.new

    # Mutex to synchronize in the exclusive method
    # Initial usage for the Ruby pipeline initialization which is not thread safe
    @webserver_control_lock = Mutex.new

    @convergence_lock = Mutex.new

    # Special bus object for inter-pipelines communications. Used by the `pipeline` input/output
    @pipeline_bus = org.logstash.plugins.pipeline.PipelineBus.create

    @pipelines_registry = LogStash::PipelinesRegistry.new

    @name = setting("node.name")
    # Generate / load the persistent uuid
    id

    # Initialize, but do not start the webserver.
    @webserver = LogStash::WebServer.from_settings(@logger, self, settings)

    # This is for backward compatibility in the tests
    if source_loader.nil?
      @source_loader = LogStash::Config::SourceLoader.new
      @source_loader.add_source(LogStash::Config::Source::Local.new(@settings))
    else
      @source_loader = source_loader
    end

    # Normalize time interval to seconds
    # we can't do .to_seconds here as values under 1 seconds are rounded to 0
    # so we get the nanos and convert to seconds instead.
    @reload_interval = setting("config.reload.interval").to_nanos * 1e-9

    @collect_metric = setting("metric.collect")

    # Create the collectors and configured it with the library
    configure_metrics_collectors

    @state_resolver = LogStash::StateResolver.new(metric)

    @pipeline_reload_metric = metric.namespace([:stats, :pipelines])
    @instance_reload_metric = metric.namespace([:stats, :reloads])
    initialize_agent_metrics
    initialize_flow_metrics

    initialize_geoip_database_metrics(metric)

    @pq_config_validator = LogStash::PersistedQueueConfigValidator.new
    @pipeline_resource_usage_validator = LogStash::PipelineResourceUsageValidator.new(Java::java.lang.Runtime.getRuntime().maxMemory)

    @dispatcher = LogStash::EventDispatcher.new(self)
    LogStash::PLUGIN_REGISTRY.hooks.register_emitter(self.class, dispatcher)
    dispatcher.fire(:after_initialize)

    @running = Concurrent::AtomicBoolean.new(false)
  end

  def execute
    @thread = Thread.current # this var is implicitly used by Stud.stop?
    LogStash::Util.set_thread_name("Agent thread")
    logger.debug("Starting agent")

    transition_to_running

    start_webserver_if_enabled

    converge_state_and_update

    if auto_reload?
      # `sleep_then_run` instead of firing the interval right away
      Stud.interval(@reload_interval, :sleep_then_run => true) do
        # TODO(ph) OK, in reality, we should get out of the loop, but I am
        # worried about the implication of that change so instead when we are stopped
        # we don't converge.
        #
        # Logstash currently expect to be block here, the signal will force a kill on the agent making
        # the agent thread unblock
        #
        # Actually what we really need is one more state:
        #
        # init => running => stopping => stopped
        converge_state_and_update unless stopped?
      end
    else
      # exit with error status if the initial converge_state_and_update did not create any pipeline
      return 1 if @pipelines_registry.empty?

      while !Stud.stop?
        # exit if all pipelines are terminated and none are reloading
        break if no_pipeline?

        # exit if there are no user defined pipelines (not system pipeline) and none are reloading
        break if !running_user_defined_pipelines?

        sleep(0.5)
      end
    end

    return 0
  ensure
    transition_to_stopped
  end

  include org.logstash.health.PipelineIndicator::PipelineDetailsProvider
  def pipeline_details(pipeline_id)
    logger.trace("fetching pipeline details for `#{pipeline_id}`")
    pipeline_id = pipeline_id.to_sym

    java_import org.logstash.health.PipelineIndicator

    pipeline_state = @pipelines_registry.states.get(pipeline_id)
    if pipeline_state.nil?
      return PipelineIndicator::Details.new(PipelineIndicator::Status::UNKNOWN)
    end

    pipeline_state.synchronize do |sync_state|
      status = case
               when sync_state.loading?    then PipelineIndicator::Status::LOADING
               when sync_state.crashed?    then PipelineIndicator::Status::TERMINATED
               when sync_state.running?    then PipelineIndicator::Status::RUNNING
               when sync_state.finished?   then PipelineIndicator::Status::FINISHED
               else                             PipelineIndicator::Status::UNKNOWN
               end

      PipelineIndicator::Details.new(status, sync_state.pipeline&.to_java.collectWorkerUtilizationFlowObservation)
    end
  end

  def auto_reload?
    @auto_reload
  end

  def running?
    @running.true?
  end

  def stopped?
    @running.false?
  end

  # Only call converge_state_and_update if agent is running
  # to avoid a double call to converge_state_and_update since
  # agent.execute will call converge_state_and_update itself
  def converge_state_and_update_if_running
    converge_state_and_update if running?
  end

  # Trigger convergence of pipelines
  # NOTE that there is no point of calling this method before
  # Agent#execute has been called since it will itself call
  # converge_state_and_update and will result in a double
  # convergence.
  def converge_state_and_update
    results = @source_loader.fetch

    unless results.success?
      if auto_reload?
        logger.debug("Could not fetch the configuration to converge, will retry", :message => results.error, :retrying_in => @reload_interval)
        return
      else
        raise "Could not fetch the configuration, message: #{results.error}"
      end
    end

    @pq_config_validator.check(@pipelines_registry.running_user_defined_pipelines, results.response)

    converge_result = resolve_actions_and_converge_state(results.response)
    update_metrics(converge_result)
    if converge_result.success? && converge_result.total > 0
      logger.info(
          "Pipelines running",
          :count => running_pipelines.size,
          :running_pipelines => running_pipelines.keys,
          :non_running_pipelines => non_running_pipelines.keys
      )
      @pipeline_resource_usage_validator.check(@pipelines_registry)
    end

    dispatch_events(converge_result)

    converge_result
  rescue => e
    attributes = {:exception => e.class, :message => e.message}
    attributes.merge!({:backtrace => e.backtrace}) if logger.debug?
    logger.error("An exception happened when converging configuration", attributes)
  end

  ##
  # Shut down a pipeline and wait for it to fully stop.
  # WARNING: Calling from `Plugin#initialize` or `Plugin#register` will result in deadlock.
  # @param pipeline_id [String]
  def stop_pipeline(pipeline_id)
    action = LogStash::PipelineAction::Stop.new(pipeline_id.to_sym)
    converge_state_with_resolved_actions([action])
  end

  # Calculate the Logstash uptime in milliseconds
  #
  # @return [Integer] Uptime in milliseconds
  def uptime
    ((Time.now.to_f - STARTED_AT.to_f) * 1000.0).to_i
  end

  def shutdown
    # Since we're shutting down we need to shutdown the DAG of pipelines that are talking to each other
    # in order of dependency.
    pipeline_bus.setBlockOnUnlisten(true)

    transition_to_stopped
    converge_result = shutdown_pipelines
    stop_collecting_metrics
    stop_webserver
    converge_result
  end

  def id
    return @id if @id

    uuid = nil
    if ::File.exist?(id_path)
      begin
        uuid = ::File.open(id_path) {|f| f.each_line.first.chomp }
      rescue => e
        logger.warn("Could not open persistent UUID file!",
                    :path => id_path,
                    :error => e.message,
                    :class => e.class.name)
      end
    end

    if !uuid
      uuid = SecureRandom.uuid
      logger.info("No persistent UUID file found. Generating new UUID",
                  :uuid => uuid,
                  :path => id_path)
      begin
        ::File.open(id_path, 'w') {|f| f.write(uuid) }
      rescue => e
        logger.warn("Could not write persistent UUID file! Will use ephemeral UUID",
                    :uuid => uuid,
                    :path => id_path,
                    :error => e.message,
                    :class => e.class.name)
      end
    end

    @id = uuid
  end

  def id_path
    @id_path ||= ::File.join(settings.get("path.data"), "uuid")
  end

  #
  # Backward compatibility proxies to the PipelineRegistry
  #

  def get_pipeline(pipeline_id)
    @pipelines_registry.get_pipeline(pipeline_id)
  end

  def pipelines_count
    @pipelines_registry.size
  end

  def running_pipelines
    @pipelines_registry.running_pipelines
   end

   def loading_pipelines
    @pipelines_registry.loading_pipelines
   end

  def loaded_pipelines
    @pipelines_registry.loaded_pipelines
  end

  def non_running_pipelines
    @pipelines_registry.non_running_pipelines
  end

  def running_pipelines?
    @pipelines_registry.running_pipelines.any?
  end

  def running_pipelines_count
    @pipelines_registry.running_pipelines.size
  end

  def running_user_defined_pipelines?
    @pipelines_registry.running_user_defined_pipelines.any?
  end

  def running_user_defined_pipelines
    @pipelines_registry.running_user_defined_pipelines
  end

  def no_pipeline?
    @pipelines_registry.running_pipelines(include_loading: true).empty?
  end

  private

  def transition_to_stopped
    @running.make_false
  end

  def transition_to_running
    @running.make_true
  end

  # @param pipeline_configs [Array<Config::PipelineConfig>]
  # @return [ConvergeResult]
  def resolve_actions_and_converge_state(pipeline_configs)
    @convergence_lock.synchronize do
      pipeline_actions = resolve_actions(pipeline_configs)
      converge_state(pipeline_actions)
    end
  end

  # Beware the usage with #resolve_actions_and_converge_state
  # Calling this method in `Plugin#register` causes deadlock.
  # For example, resolve_actions_and_converge_state -> pipeline reload_action -> plugin register -> converge_state_with_resolved_actions
  def converge_state_with_resolved_actions(pipeline_actions)
    @convergence_lock.synchronize do
      converge_state(pipeline_actions)
    end
  end

  # We depends on a series of task derived from the internal state and what
  # need to be run, theses actions are applied to the current pipelines to converge to
  # the desired state.
  #
  # The current actions are simple and favor composition, allowing us to experiment with different
  # way to making them and also test them in isolation with the current running agent.
  #
  # Currently only action related to pipeline exist, but nothing prevent us to use the same logic
  # for other tasks.
  #
  def converge_state(pipeline_actions)
    logger.debug("Converging pipelines state", :actions_count => pipeline_actions.size)
    fail("Illegal access to `LogStash::Agent#converge_state()` without exclusive lock at #{caller[1]}") unless @convergence_lock.owned?

    converge_result = LogStash::ConvergeResult.new(pipeline_actions.size)

    @running_action_threads = {}

    slow_start_monitor = SlowStartMonitor.new(self)
    slow_start_monitor.start_creating_pipelines do |still_loading_pipelines|
      logger.warn("Starving pipelines loading", :slow_pipelines => still_loading_pipelines)
      if auto_reload?
        # retrieve the pipelines config and compute which Reload actions are present
        results = @source_loader.fetch
        if results.success?
          pipeline_configs = results.response
          pipeline_actions = resolve_actions(pipeline_configs)
          reload_pipeline_ids = pipeline_actions
                .select {|action| action.is_a?(LogStash::PipelineAction::Reload)}
                .map {|action| action.pipeline_id}
          pipelines_to_force_kill = reload_pipeline_ids & still_loading_pipelines
          logger.warn("Pipelines to be killed: ", :pipelines_to_force_kill => pipelines_to_force_kill)
          pipelines_to_force_kill.each do |pipeline_id|
            @running_action_threads[pipeline_id].kill
          end
        end
      end
    end

    pipeline_actions.map do |action|
      @running_action_threads[action.pipeline_id] = Thread.new(action, converge_result) do |action, converge_result|
        LogStash::Util.set_thread_name("Converge #{action}")
        # We execute every task we need to converge the current state of pipelines
        # for every task we will record the action result, that will help us
        # the results of all the task will determine if the converge was successful or not
        #
        # The ConvergeResult#add, will accept the following values
        #  - boolean
        #  - FailedAction
        #  - SuccessfulAction
        #  - Exception
        #
        # This give us a bit more extensibility with the current startup/validation model
        # that we currently have.
        begin
          logger.debug("Executing action", :action => action)
          action_result = action.execute(self, @pipelines_registry)
          converge_result.add(action, action_result)

          unless action_result.successful?
            logger.error("Failed to execute action",
              :id => action.pipeline_id,
              :action_type => action_result.class,
              :message => action_result.message,
              :backtrace => action_result.backtrace
            )
          end
        rescue SystemExit, Exception => e
          error_details = { :action => action, :exception => e.class.name, :message => e.message, :backtrace => e.backtrace }
          cause = e.cause
          if cause && e != cause
            error_details[:cause] = { :exception => cause.class, :message => cause.message }
            error_details[:cause][:backtrace] = cause.backtrace if cause.backtrace
          end
          logger.error('Failed to execute action', error_details)
          converge_result.add(action, LogStash::ConvergeResult::FailedAction.from_exception(e))
        end
      end
    end.each(&:join)

    slow_start_monitor.finished_pipeline_creation

    logger.trace? && logger.trace("Converge results",
      :success => converge_result.success?,
      :failed_actions => converge_result.failed_actions.collect { |a, r| "id: #{a.pipeline_id}, action_type: #{a.class}, message: #{r.message}" },
      :successful_actions => converge_result.successful_actions.collect { |a, r| "id: #{a.pipeline_id}, action_type: #{a.class}" }
    )

    converge_result
  end

  def resolve_actions(pipeline_configs)
#     fail("Illegal access to `LogStash::Agent#resolve_actions()` without exclusive lock at #{caller[1]}") unless @convergence_lock.owned?
    @state_resolver.resolve(@pipelines_registry, pipeline_configs)
  end

  def dispatch_events(converge_results)
    converge_results.successful_actions.each do |action, _|
      case action
      when LogStash::PipelineAction::Create
        dispatcher.fire(:pipeline_started, get_pipeline(action.pipeline_id))
      when LogStash::PipelineAction::Reload
        dispatcher.fire(:pipeline_stopped, get_pipeline(action.pipeline_id))
      when LogStash::PipelineAction::Stop
        dispatcher.fire(:pipeline_stopped, get_pipeline(action.pipeline_id))
      end
    end
  end

  def start_webserver_if_enabled
    if @settings.get_value("api.enabled")
      start_webserver
    else
      @logger.info("HTTP API is disabled (`api.enabled=false`); webserver will not be started.")
    end
  end

  def start_webserver
    @webserver_control_lock.synchronize do
      @webserver_thread = Thread.new(@webserver) do |webserver|
        LogStash::Util.set_thread_name("Api Webserver")
        webserver.run
      end
    end
  end

  def stop_webserver
    @webserver_control_lock.synchronize do
      if @webserver_thread
        @webserver.stop
        if @webserver_thread.join(5).nil?
          @webserver_thread.kill
          @webserver_thread.join
        end
      end
    end
  end

  def configure_metrics_collectors
    @collector = LogStash::Instrument::Collector.new

    @metric = if collect_metrics?
      @logger.debug("Setting up metric collection")
      LogStash::Instrument::Metric.new(@collector)
    else
      LogStash::Instrument::NullMetric.new(@collector)
    end

    @periodic_pollers = LogStash::Instrument::PeriodicPollers.new(@metric, settings.get("queue.type"), self)
    @periodic_pollers.start
  end

  def stop_collecting_metrics
    @periodic_pollers.stop
  end

  def collect_metrics?
    @collect_metric
  end

  def shutdown_pipelines
    logger.debug("Shutting down all pipelines", :pipelines_count => running_pipelines_count)

    # In this context I could just call shutdown, but I've decided to
    # use the stop action implementation for that so we have the same code.
    # This also give us some context into why a shutdown is failing
    resolve_actions_and_converge_state([]) # We stop all the pipeline, so we converge to a empty state
  end

  def setting(key)
    @settings.get(key)
  end

  # Methods related to the creation of all metrics
  # related to states changes and failures
  #
  # I think we could use an observer here to decouple the metrics, but moving the code
  # into separate function is the first step we take.
  def update_metrics(converge_result)
    converge_result.failed_actions.each do |action, action_result|
      update_failures_metrics(action, action_result)
    end

    converge_result.successful_actions.each do |action, action_result|
      update_success_metrics(action, action_result)
    end
  end

  def update_success_metrics(action, action_result)
    case action
      when LogStash::PipelineAction::Create
        # When a pipeline is successfully created we create the metric
        # place holder related to the lifecycle of the pipeline
        initialize_pipeline_metrics(action)
      when LogStash::PipelineAction::Reload
        update_successful_reload_metrics(action, action_result)
    end
  end

  def update_failures_metrics(action, action_result)
    if action.is_a?(LogStash::PipelineAction::Create)
      # force to create the metric fields
      initialize_pipeline_metrics(action)
    end

    @instance_reload_metric.increment(:failures)

    @pipeline_reload_metric.namespace([action.pipeline_id, :reloads]).tap do |n|
      n.increment(:failures)
      n.gauge(:last_error, { :message => action_result.message, :backtrace => action_result.backtrace})
      n.gauge(:last_failure_timestamp, LogStash::Timestamp.now)
    end
  end

  def initialize_agent_metrics
    @instance_reload_metric.increment(:successes, 0)
    @instance_reload_metric.increment(:failures, 0)
  end

  def initialize_flow_metrics
    if collect_metrics? && metric.collector

      java_import org.logstash.instrument.metrics.UptimeMetric
      java_import org.logstash.instrument.metrics.UptimeMetric::ScaleUnits

      uptime_metric = UptimeMetric.new
      uptime_precise_millis = uptime_metric.with_units_precise(ScaleUnits::MILLISECONDS)
      uptime_precise_seconds = uptime_metric.with_units_precise(ScaleUnits::SECONDS)

      events_namespace = metric.namespace([:stats, :events])
      flow_metrics = []
      flow_metrics << create_flow_metric("input_throughput", get_counter(events_namespace, :in), uptime_precise_seconds)
      flow_metrics << create_flow_metric("filter_throughput", get_counter(events_namespace, :out), uptime_precise_seconds)
      flow_metrics << create_flow_metric("output_throughput", get_counter(events_namespace, :filtered), uptime_precise_seconds)
      flow_metrics << create_flow_metric("queue_backpressure", get_timer(events_namespace, :queue_push_duration_in_millis), uptime_precise_millis)
      flow_metrics << create_flow_metric("worker_concurrency", get_timer(events_namespace, :duration_in_millis), uptime_precise_millis)

      registered, unregistered = flow_metrics.partition do |flow_metric|
        @metric.collector.register?([:stats, :flow], flow_metric.name.to_sym, flow_metric)
      end

      unregistered.each do |unregistered_flow_metric|
        logger.warn("Failed to register global flow metric #{unregistered_flow_metric.name}.")
      end

      @flow_metrics = registered.freeze
    end
  end

  def get_counter(namespace, key)
    org.logstash.instrument.metrics.counter.LongCounter.fromRubyBase(namespace, key)
  end
  private :get_counter

  def get_timer(namespace, key)
    org.logstash.instrument.metrics.timer.TimerMetric.fromRubyBase(namespace, key)
  end
  private :get_timer

  def create_flow_metric(name, numerator_metric, denominator_metric)
    org.logstash.instrument.metrics.FlowMetric.create(name, numerator_metric, denominator_metric)
  end
  private :create_flow_metric

  def capture_flow_metrics
    @flow_metrics&.each(&:capture)
  end
  public :capture_flow_metrics

  def initialize_pipeline_metrics(action)
    @pipeline_reload_metric.namespace([action.pipeline_id, :reloads]).tap do |n|
      n.increment(:successes, 0)
      n.increment(:failures, 0)
      n.gauge(:last_error, nil)
      n.gauge(:last_success_timestamp, nil)
      n.gauge(:last_failure_timestamp, nil)
    end
  end

  def update_successful_reload_metrics(action, action_result)
    @instance_reload_metric.increment(:successes)

    @pipeline_reload_metric.namespace([action.pipeline_id, :reloads]).tap do |n|
      n.increment(:successes)
      n.gauge(:last_success_timestamp, action_result.executed_at)
    end
  end

  def initialize_geoip_database_metrics(metric)
    begin
      relative_path = ::File.join(LogStash::Environment::LOGSTASH_HOME, "x-pack", "lib", "geoip_database_management")
      require_relative ::File.join(relative_path, "manager")
      require_relative ::File.join(relative_path, "metric")

      geoip_metric = metric.namespace([:geoip_download_manager]).tap do |n|
        db = n.namespace([:database])
        [:ASN, :City].each do  |database_type|
          db_type = db.namespace([database_type])
          db_type.gauge(:status, nil)
          db_type.gauge(:last_updated_at, nil)
          db_type.gauge(:fail_check_in_days, 0)
        end

        dl = n.namespace([:download_stats])
        dl.increment(:successes, 0)
        dl.increment(:failures, 0)
        dl.gauge(:last_checked_at, nil)
        dl.gauge(:status, nil)
      end

      database_metric = LogStash::GeoipDatabaseManagement::Metric.new(geoip_metric)
      database_manager = LogStash::GeoipDatabaseManagement::Manager.instance
      database_manager.database_metric = database_metric
    rescue LoadError => e
      @logger.trace("DatabaseManager is not in classpath", exception: e.message, backtrace: e.backtrace)
    end
  end
end # class LogStash::Agent


class SlowStartMonitor
  include LogStash::Util::Loggable

  attr_reader :logger

  def initialize(agent)
    @logger = self.class.logger
    @monitor_thread = nil
    @monitoring_interval = 5 #seconds
    @agent = agent
  end

  def start_creating_pipelines(&block)
    @thread = Thread.new do
      Stud.interval(@monitoring_interval, :sleep_then_run => true) do
        pipeline_names = @agent.loading_pipelines.keys
        if !Stud.stop?
          still_loading_pipelines = @agent.loading_pipelines.keys & pipeline_names
#           logger.warn("Starving pipelines loading", :slow_pipelines => still_loading_pipelines)
          block.call(still_loading_pipelines)
        end
      end
    end
  end

  def finished_pipeline_creation
    Stud.stop!(@thread)
  end
end