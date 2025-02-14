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

require "thread"
require "concurrent"
require "thwait"
require "logstash/filters/base"
require "logstash/inputs/base"
require "logstash/outputs/base"
require "logstash/instrument/collector"
require "logstash/compiler"
require "logstash/config/lir_serializer"
require "logstash/worker_loop_thread"

module LogStash; class JavaPipeline < JavaBasePipeline
  include LogStash::Util::Loggable

  java_import org.apache.logging.log4j.ThreadContext

  attr_reader \
    :worker_threads,
    :input_threads,
    :events_consumed,
    :events_filtered,
    :started_at,
    :thread

  MAX_INFLIGHT_WARN_THRESHOLD = 10_000
  SECOND = 1
  MEMORY = "memory".freeze

  def initialize(pipeline_config, namespaced_metric = nil, agent = nil)
    @logger = self.logger
    super pipeline_config, namespaced_metric, @logger, agent
    open_queue

    @worker_threads = []

    @drain_queue =  settings.get_value("queue.drain") || settings.get("queue.type") == MEMORY

    @events_filtered = java.util.concurrent.atomic.LongAdder.new
    @events_consumed = java.util.concurrent.atomic.LongAdder.new

    @input_threads = []
    # @ready requires thread safety since it is typically polled from outside the pipeline thread
    @ready = Concurrent::AtomicBoolean.new(false)
    @running = Concurrent::AtomicBoolean.new(false)
    @flushing = java.util.concurrent.atomic.AtomicBoolean.new(false)
    @flushRequested = java.util.concurrent.atomic.AtomicBoolean.new(false)
    @shutdownRequested = java.util.concurrent.atomic.AtomicBoolean.new(false)
    @outputs_registered = Concurrent::AtomicBoolean.new(false)

    # @finished_execution signals that the pipeline thread has finished its execution
    # regardless of any exceptions; it will always be true when the thread completes
    @finished_execution = Concurrent::AtomicBoolean.new(false)

    # @finished_run signals that the run methods called in the pipeline thread was completed
    # without errors and it will NOT be set if the run method exits from an exception; this
    # is by design and necessary for the wait_until_started semantic
    @finished_run = Concurrent::AtomicBoolean.new(false)

    if settings.get('pipeline.ecs_compatibility') == "v2"
      deprecation_logger.deprecated I18n.t("logstash.pipeline.ecs_compatibility.v2_deprecated")
    end

    @thread = nil
  end # def initialize

  def finished_execution?
    @finished_execution.true?
  end

  def ready?
    @ready.value
  end

  def safe_pipeline_worker_count
    default = settings.get_default("pipeline.workers")
    pipeline_workers = settings.get("pipeline.workers") #override from args "-w 8" or config
    safe_filters, unsafe_filters = filters.partition(&:threadsafe?)
    plugins = unsafe_filters.collect { |f| f.config_name }

    return pipeline_workers if unsafe_filters.empty?

    if settings.set?("pipeline.workers")
      if pipeline_workers > 1
        @logger.warn("Warning: Manual override - there are filters that might not work with multiple worker threads", default_logging_keys(:worker_threads => pipeline_workers, :filters => plugins))
      end
    else
      # user did not specify a worker thread count
      # warn if the default is multiple
      if default > 1
        @logger.warn("Defaulting pipeline worker threads to 1 because there are some filters that might not work with multiple worker threads",
                     default_logging_keys(:count_was => default, :filters => plugins))
        return 1 # can't allow the default value to propagate if there are unsafe filters
      end
    end
    pipeline_workers
  end

  def filters?
    filters.any?
  end

  def start
    # Since we start lets assume that the metric namespace is cleared
    # this is useful in the context of pipeline reloading
    collect_stats
    collect_dlq_stats

    @logger.debug("Starting pipeline", default_logging_keys)

    @finished_execution.make_false
    @finished_run.make_false

    @thread = Thread.new do
      error_log_params = ->(e) {
        default_logging_keys(
          :exception => e,
          :backtrace => e.backtrace,
          "pipeline.sources" => pipeline_source_details
        )
      }

      begin
        LogStash::Util.set_thread_name("pipeline.#{pipeline_id}")
        ThreadContext.put("pipeline.id", pipeline_id)
        run
        @finished_run.make_true
      rescue => e
        logger.error("Pipeline error", error_log_params.call(e))
      ensure
        # we must trap any exception here to make sure the following @finished_execution
        # is always set to true regardless of any exception before in the close method call
        begin
          close
        rescue => e
          logger.error("Pipeline close error, ignoring", error_log_params.call(e))
        end
        @finished_execution.make_true
        @logger.info("Pipeline terminated", "pipeline.id" => pipeline_id)
      end
    end

    status = wait_until_started

    if status
      logger.debug("Pipeline started successfully", default_logging_keys(:pipeline_id => pipeline_id))
    end

    status
  end

  def wait_until_started
    while true do
      if @finished_run.true?
        # it completed run without exception
        return true
      elsif thread.nil? || !thread.alive?
        # some exception occurred and the thread is dead
        return false
      elsif running?
        # fully initialized and running
        return true
      else
        sleep 0.01
      end
    end
  end

  def run
    @started_at = Time.now
    @thread = Thread.current
    Util.set_thread_name("[#{pipeline_id}]-pipeline-manager")

    start_workers

    @logger.info("Pipeline started", "pipeline.id" => pipeline_id)

    # Block until all inputs have stopped
    # Generally this happens if SIGINT is sent and `shutdown` is called from an external thread

    transition_to_running
    start_flusher # Launches a non-blocking thread for flush events
    begin
      monitor_inputs_and_workers
    ensure
      transition_to_stopped

      shutdown_flusher
      shutdown_workers

      close
    end
    @logger.debug("Pipeline has been shutdown", default_logging_keys)
  end

  def transition_to_running
    @running.make_true
  end

  def transition_to_stopped
    @running.make_false
  end

  def running?
    @running.true?
  end

  def stopped?
    @running.false?
  end

  # register_plugins calls #register_plugin on the plugins list and upon exception will call Plugin#do_close on all registered plugins
  # @param plugins [Array[Plugin]] the list of plugins to register
  def register_plugins(plugins)
    registered = []
    plugins.each do |plugin|
      plugin.register
      registered << plugin
    end
  rescue => e
    registered.each(&:do_close)
    raise e
  end

  def start_workers
    @worker_threads.clear # In case we're restarting the pipeline
    @outputs_registered.make_false
    begin
      maybe_setup_out_plugins

      pipeline_workers = safe_pipeline_worker_count
      @preserve_event_order = preserve_event_order?(pipeline_workers)
      batch_size = settings.get("pipeline.batch.size")
      batch_delay = settings.get("pipeline.batch.delay")

      max_inflight = batch_size * pipeline_workers

      config_metric = metric.namespace([:stats, :pipelines, pipeline_id.to_s.to_sym, :config])
      config_metric.gauge(:workers, pipeline_workers)
      config_metric.gauge(:batch_size, batch_size)
      config_metric.gauge(:batch_delay, batch_delay)
      config_metric.gauge(:config_reload_automatic, settings.get("config.reload.automatic"))
      config_metric.gauge(:config_reload_interval, settings.get("config.reload.interval").to_nanos)
      config_metric.gauge(:dead_letter_queue_enabled, dlq_enabled?)
      config_metric.gauge(:dead_letter_queue_path, dlq_writer.get_path.to_absolute_path.to_s) if dlq_enabled?
      config_metric.gauge(:ephemeral_id, ephemeral_id)
      config_metric.gauge(:hash, lir.unique_hash)
      config_metric.gauge(:graph, ::LogStash::Config::LIRSerializer.serialize(lir))

      pipeline_log_params = default_logging_keys(
        "pipeline.workers" => pipeline_workers,
        "pipeline.batch.size" => batch_size,
        "pipeline.batch.delay" => batch_delay,
        "pipeline.max_inflight" => max_inflight,
        "pipeline.sources" => pipeline_source_details)
      @logger.info("Starting pipeline", pipeline_log_params)

      if max_inflight > MAX_INFLIGHT_WARN_THRESHOLD
        @logger.warn("CAUTION: Recommended inflight events max exceeded! Logstash will run with up to #{max_inflight} events in memory in your current configuration. If your message sizes are large this may cause instability with the default heap size. Please consider setting a non-standard heap size, changing the batch size (currently #{batch_size}), or changing the number of pipeline workers (currently #{pipeline_workers})", default_logging_keys)
      end

      filter_queue_client.set_batch_dimensions(batch_size, batch_delay)

      # First launch WorkerLoop initialization in separate threads which concurrently
      # compiles and initializes the worker pipelines

      workers_init_start = Time.now
      worker_loops = pipeline_workers.times
        .map { Thread.new { init_worker_loop } }
        .map(&:value)
      workers_init_elapsed = Time.now - workers_init_start

      fail("Some worker(s) were not correctly initialized") if worker_loops.any?{|v| v.nil?}

      @logger.info("Pipeline Java execution initialization time", "seconds" => workers_init_elapsed.round(2))

      # Once all WorkerLoop have been initialized run them in separate threads

      worker_loops.each_with_index do |worker_loop, t|
        thread = WorkerLoopThread.new(worker_loop) do
          Util.set_thread_name("[#{pipeline_id}]>worker#{t}")
          ThreadContext.put("pipeline.id", pipeline_id)
          begin
            worker_loop.run
          rescue => e
            # WorkerLoop.run() catches all Java Exception class and re-throws as IllegalStateException with the
            # original exception as the cause
            @logger.error(
              "Pipeline worker error, the pipeline will be stopped",
              default_logging_keys(:error => e.cause.message, :exception => e.cause.class, :backtrace => e.cause.backtrace)
            )
          end
        end
        @worker_threads << thread
      end

      # Finally inputs should be started last, after all workers have been initialized and started

      begin
        start_inputs
      rescue => e
        # if there is any exception in starting inputs, make sure we shutdown workers.
        # exception will already by logged in start_inputs
        shutdown_workers
        raise e
      end
    ensure
      # it is important to guarantee @ready to be true after the startup sequence has been completed
      # to potentially unblock the shutdown method which may be waiting on @ready to proceed
      @ready.make_true
    end
  end

  def resolve_cluster_uuids
    outputs.each_with_object(Set.new) do |output, cluster_uuids|
      if LogStash::PluginMetadata.exists?(output.id)
        cluster_uuids << LogStash::PluginMetadata.for_plugin(output.id).get(:cluster_uuid)
      end
    end.to_a.compact
  end

  def monitor_inputs_and_workers
    twait = ThreadsWait.new(*(@input_threads + @worker_threads))

    loop do
      break if @input_threads.empty?

      terminated_thread = twait.next_wait

      if @input_threads.delete(terminated_thread).nil?
        # this is an abnormal worker thread termination, we need to terminate the pipeline

        @worker_threads.delete(terminated_thread)

        # before terminating the pipeline we need to close the inputs
        stop_inputs

        # wait 10 seconds for all input threads to terminate
        wait_input_threads_termination(10 * SECOND) do
          @logger.warn("Waiting for input plugin to close", default_logging_keys)
          sleep(1)
        end

        if inputs_running? && settings.get("queue.type") == MEMORY
          # if there are still input threads alive they are probably blocked pushing on the memory queue
          # because no worker is present to consume from the ArrayBlockingQueue
          # if this is taking too long we have a problem
          wait_input_threads_termination(10 * SECOND) do
            dropped_batch = filter_queue_client.read_batch
            @logger.error("Dropping events to unblock input plugin", default_logging_keys(:count => dropped_batch.filteredSize)) if dropped_batch.filteredSize > 0
          end
        end

        raise("Unable to stop input plugin(s)") if inputs_running?

        break
      end
    end

    @logger.debug("Input plugins stopped! Will shutdown filter/output workers.", default_logging_keys)
  end

  def start_inputs
    moreinputs = []
    inputs.each do |input|
      if input.threadable && input.threads > 1
        (input.threads - 1).times do |i|
          moreinputs << input.clone
        end
      end
    end
    moreinputs.each {|i| inputs << i}

    # first make sure we can register all input plugins
    register_plugins(inputs)

    # then after all input plugins are successfully registered, start them
    inputs.each { |input| start_input(input) }
  end

  def start_input(plugin)
    if plugin.class == LogStash::JavaInputDelegator
      @input_threads << plugin.start
    else
      @input_threads << Thread.new { inputworker(plugin) }
    end
  end

  def inputworker(plugin)
    Util::set_thread_name("[#{pipeline_id}]<#{plugin.class.config_name}")
    ThreadContext.put("pipeline.id", pipeline_id)
    ThreadContext.put("plugin.id", plugin.id)
    begin
      plugin.run(wrapped_write_client(plugin.id.to_sym))
    rescue => e
      if plugin.stop?
        @logger.debug(
          "Input plugin raised exception during shutdown, ignoring it.",
           default_logging_keys(
             :plugin => plugin.class.config_name,
             :exception => e.message,
             :backtrace => e.backtrace))
        return
      end

      # otherwise, report error and restart
      @logger.error(I18n.t(
        "logstash.pipeline.worker-error-debug",
        default_logging_keys(
          :plugin => plugin.inspect,
          :error => e.message,
          :exception => e.class,
          :stacktrace => e.backtrace.join("\n"))))

      # Assuming the failure that caused this exception is transient,
      # let's sleep for a bit and execute #run again
      sleep(1)
      close_plugin_and_ignore(plugin)
      retry
    ensure
      close_plugin_and_ignore(plugin)
    end
  end

  # initiate the pipeline shutdown sequence
  # this method is intended to be called from outside the pipeline thread
  # and will block until the pipeline has successfully shut down.
  def shutdown
    return if finished_execution?
    # shutdown can only start once the pipeline has completed its startup.
    # avoid potential race condition between the startup sequence and this
    # shutdown method which can be called from another thread at any time
    sleep(0.1) while !ready?

    # TODO: should we also check against calling shutdown multiple times concurrently?
    stop_inputs
    wait_for_shutdown
    clear_pipeline_metrics
  end # def shutdown

  def wait_for_shutdown
    ShutdownWatcher.new(self).start
  end

  def stop_inputs
    @logger.debug("Closing inputs", default_logging_keys)
    inputs.each(&:do_stop)
    @logger.debug("Closed inputs", default_logging_keys)
  end

  # After `shutdown` is called from an external thread this is called from the main thread to
  # tell the worker threads to stop and then block until they've fully stopped
  # This also stops all filter and output plugins
  def shutdown_workers
    @shutdownRequested.set(true)

    @worker_threads.each do |t|
      @logger.debug("Shutdown waiting for worker thread" , default_logging_keys(:thread => t.inspect))
      t.join
    end

    filters.each(&:do_close)
    outputs.each(&:do_close)
  end

  # for backward compatibility in devutils for the rspec helpers, this method is not used
  # anymore and just here to not break TestPipeline that inherits this class.
  def filter(event, &block)
  end

  # for backward compatibility in devutils for the rspec helpers, this method is not used
  # anymore and just here to not break TestPipeline that inherits this class.
  def flush_filters(options = {}, &block)
  end

  def start_flusher
    # Invariant to help detect improper initialization
    raise "Attempted to start flusher on a stopped pipeline!" if stopped?
    @flusher_thread = org.logstash.execution.PeriodicFlush.new(@flushRequested, @flushing)
    @flusher_thread.start
  end

  def shutdown_flusher
    @flusher_thread.close
  end

  # Calculate the uptime in milliseconds
  #
  # @return [Fixnum] Uptime in milliseconds, 0 if the pipeline is not started
  def uptime
    return 0 if started_at.nil?
    ((Time.now.to_f - started_at.to_f) * 1000.0).to_i
  end

  def plugin_threads_info
    input_threads = @input_threads.select {|t| t.class == Thread && t.alive? }
    worker_threads = @worker_threads.select {|t| t.alive? }
    (input_threads + worker_threads).map {|t| Util.thread_info(t) }
  end

  def stalling_threads_info
    all_threads = plugin_threads_info
    all_threads << Util.thread_info(@thread) if @thread

    all_threads
      .reject {|t| t["blocked_on"] } # known benign blocking statuses
      .each {|t| t.delete("backtrace") }
      .each {|t| t.delete("blocked_on") }
      .each {|t| t.delete("status") }
  end

  def clear_pipeline_metrics
    # TODO(ph): I think the metric should also proxy that call correctly to the collector
    # this will simplify everything since the null metric would simply just do a noop
    collector = metric.collector

    unless collector.nil?
      # selectively reset metrics we don't wish to keep after reloading
      # these include metrics about the plugins and number of processed events
      # we want to keep other metrics like reload counts and error messages
      collector.clear("stats/pipelines/#{pipeline_id}/plugins")
      collector.clear("stats/pipelines/#{pipeline_id}/events")
    end
  end

  # Sometimes we log stuff that will dump the pipeline which may contain
  # sensitive information (like the raw syntax tree which can contain passwords)
  # We want to hide most of what's in here
  def inspect
    {
      :pipeline_id => pipeline_id,
      :settings => settings.inspect,
      :ready => @ready,
      :running => @running,
      :flushing => @flushing
    }
  end

  def shutdown_requested?
    @shutdownRequested.get
  end

  def worker_threads_draining?
    @worker_threads.any? {|t| t.worker_loop.draining? }
  end

  private

  def close_plugin_and_ignore(plugin)
    begin
      plugin.do_close
    rescue => e
      @logger.warn(
        "plugin raised exception while closing, ignoring",
        default_logging_keys(
          :plugin => plugin.class.config_name,
          :exception => e.message,
          :backtrace => e.backtrace))
    end
  end

  # @return [WorkerLoop] a new WorkerLoop instance or nil upon construction exception
  def init_worker_loop
    begin
      org.logstash.execution.WorkerLoop.new(
        lir_execution,
        filter_queue_client,
        @events_filtered,
        @events_consumed,
        @flushRequested,
        @flushing,
        @shutdownRequested,
        @drain_queue,
        @preserve_event_order)
    rescue => e
      @logger.error(
        "Worker loop initialization error",
        default_logging_keys(:error => e.message, :exception => e.class, :stacktrace => e.backtrace.join("\n")))
      nil
    end
  end

  def maybe_setup_out_plugins
    if @outputs_registered.make_true
      register_plugins(outputs)
      register_plugins(filters)
    end
  end

  def default_logging_keys(other_keys = {})
    keys = {:pipeline_id => pipeline_id}.merge other_keys
    keys[:thread] ||= thread.inspect if thread
    keys
  end

  def preserve_event_order?(pipeline_workers)
    case settings.get("pipeline.ordered")
    when "auto"
      if settings.set?("pipeline.workers") && settings.get("pipeline.workers") == 1
        @logger.warn("'pipeline.ordered' is enabled and is likely less efficient, consider disabling if preserving event order is not necessary")
        return true
      end
    when "true"
      fail("enabling the 'pipeline.ordered' setting requires the use of a single pipeline worker") if pipeline_workers > 1
      return true
    end

    false
  end

  def wait_input_threads_termination(timeout_seconds, &block)
    start = Time.now
    seconds = 0
    while inputs_running? && (seconds < timeout_seconds)
      block.call
      seconds = Time.now - start
    end
  end

  def inputs_running?
    @input_threads.any?(&:alive?)
  end

end; end
