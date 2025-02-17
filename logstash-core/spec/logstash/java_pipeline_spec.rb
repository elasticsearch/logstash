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

require "spec_helper"
require "logstash/inputs/generator"
require "logstash/filters/drop"
require_relative "../support/mocks_classes"
require_relative "../support/helpers"
require 'support/pipeline/pipeline_helpers'
require 'logstash/pipeline_action/reload'
require "stud/try"
require 'timeout'
require "thread"

class DummyInput < LogStash::Inputs::Base
  config_name "dummyinput"
  milestone 2

  def register
  end

  def run(queue)
  end

  def close
  end
end

class DummyManualInputGenerator < LogStash::Inputs::Base
  config_name "dummymanualinputgenerator"
  config :iterations, :validate => :number
  milestone 2

  attr_accessor :keep_running

  def initialize(*args)
    super(*args)
    @keep_running = Concurrent::AtomicBoolean.new(false)
    @queue = nil
  end

  def register
  end

  def run(queue)
    @queue = queue
    if @iterations
      @iterations.times do |i|
        queue << LogStash::Event.new
        sleep(0.5)
      end
    else
      while !stop? || @keep_running.true?
        queue << LogStash::Event.new
        sleep(0.5)
      end
    end
  end

  def push_once
    @queue << LogStash::Event.new
  end
end

class DummyCrashingInput  < LogStash::Inputs::Base
  config_name "dummycrashinginput"

  config :on_register, :validate => :boolean

  def register
    raise(LogStash::ConfigurationError, 'crashing input on register') if @on_register
  end

  def run(queue)
    while !stop?
      queue << LogStash::Event.new
      sleep(0.5)
    end
  end
end

class DummyCodec < LogStash::Codecs::Base
  config_name "dummycodec"
  milestone 2

  config :format, :validate => :string

  def decode(data)
    data
  end

  def encode(event)
    event
  end

  def close
  end
end

class DummyOutputMore < ::LogStash::Outputs::DummyOutput
  config_name "dummyoutputmore"
end

class DummyAbortingOutput < ::LogStash::Outputs::DummyOutput
  config_name "dummyabortingoutput"

  def multi_receive(batch)
    while !execution_context&.pipeline&.shutdown_requested?
      # wait for shutdown simulating a not consumed batch
      sleep 1
    end

    # raise the exception
    java_import org.logstash.execution.AbortedBatchException
    raise AbortedBatchException.new
  end
end

class DummyFilter < LogStash::Filters::Base
  config_name "dummyfilter"
  milestone 2

  def register() end

  def filter(event) end

  def threadsafe?() false; end

  def close() end
end

class DummyCrashingFilter < LogStash::Filters::Base
  config_name "dummycrashingfilter"
  milestone 2

  def register; end

  def filter(event)
    raise("crashing filter")
  end
end

class DummySafeFilter < LogStash::Filters::Base
  config_name "dummysafefilter"
  milestone 2

  def register() end

  def filter(event) end

  def threadsafe?() true; end

  def close() end
end

class DummyFlushingFilter < LogStash::Filters::Base
  config_name "dummyflushingfilter"
  milestone 2

  def register() end
  def filter(event) end

  def periodic_flush
    true
  end

  def flush(options)
    [::LogStash::Event.new("message" => "dummy_flush")]
  end

  def close() end
end

class DummyFlushingFilterPeriodic < DummyFlushingFilter
  config_name "dummyflushingfilterperiodic"

  def flush(options)
    # Don't generate events on the shutdown flush to make sure we actually test the
    # periodic flush.
    options[:final] ? [] : [::LogStash::Event.new("message" => "dummy_flush")]
  end
end

class NilFlushingFilterPeriodic < DummyFlushingFilter
  config_name "nilflushingfilterperiodic"

  def register
    @count = 0
  end

  def flush(options)
    # Just returns nil as some plugins do at times
    @count += 1
    @count > 2 ? [::LogStash::Event.new("message" => "dummy_flush")] : nil
  end
end

describe LogStash::JavaPipeline do
  let(:worker_thread_count)     { 5 }
  let(:safe_thread_count)       { 1 }
  let(:override_thread_count)   { 42 }
  let(:dead_letter_queue_enabled) { false }
  let(:dead_letter_queue_path) { }
  let(:pipeline_settings_obj) { LogStash::SETTINGS.clone }
  let(:pipeline_settings) do
    {
      "dead_letter_queue.enable" => dead_letter_queue_enabled,
      "path.dead_letter_queue" => dead_letter_queue_path
    }
  end
  let(:max_retry) {10} #times
  let(:timeout) {120} #seconds

  before :each do
    pipeline_workers_setting = LogStash::SETTINGS.get_setting("pipeline.workers")
    allow(pipeline_workers_setting).to receive(:default).and_return(worker_thread_count)

    pipeline_settings.each {|k, v| pipeline_settings_obj.set(k, v) }
  end

  after :each do
    Thread.abort_on_exception = false
  end
  
  describe "#ephemeral_id" do
    it "creates an ephemeral_id at creation time" do
      pipeline = mock_java_pipeline_from_string("input { generator { count =>  1 } } output { null {} }")
      expect(pipeline.ephemeral_id).to_not be_nil
      pipeline.close

      second_pipeline = mock_java_pipeline_from_string("input { generator { count => 1 } } output { null {} }")
      expect(second_pipeline.ephemeral_id).not_to eq(pipeline.ephemeral_id)
      second_pipeline.close
    end
  end

  describe "aliased plugin instantiation" do
    it "should create the pipeline as if it's using the original plugin" do
      alias_registry = Java::org.logstash.plugins.AliasRegistry.new({["input", "alias"] => "generator"})
      LogStash::PLUGIN_REGISTRY = LogStash::Plugins::Registry.new alias_registry
      pipeline = mock_java_pipeline_from_string("input { alias { count => 1 } } output { null {} }")
      expect(pipeline.ephemeral_id).to_not be_nil
      pipeline.close
    end
  end

  describe "event cancellation" do
    # test harness for https://github.com/elastic/logstash/issues/6055

    let(:output) { LogStash::Outputs::DummyOutputWithEventsArray.new }

    before do
      allow(LogStash::Plugin).to receive(:lookup).with("input", "generator").and_return(LogStash::Inputs::Generator)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutputwitheventsarray").and_return(LogStash::Outputs::DummyOutputWithEventsArray)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "drop").and_call_original
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "mutate").and_call_original
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_call_original
      allow(LogStash::Outputs::DummyOutputWithEventsArray).to receive(:new).with(any_args).and_return(output)
    end

    let(:config) do
      <<-CONFIG
        input {
          generator {
            lines => ["1", "2", "END"]
            count => 1
          }
        }
        filter {
          if [message] == "1" {
            drop {}
          }
          mutate { add_tag => ["notdropped"] }
        }
        output { dummyoutputwitheventsarray {} }
      CONFIG
    end

    it "should not propagate cancelled events from filter to output" do
      abort_on_exception_state = Thread.abort_on_exception
      Thread.abort_on_exception = true

      pipeline = mock_java_pipeline_from_string(config, pipeline_settings_obj)
      Timeout.timeout(timeout) do
        pipeline.start
        sleep 0.01 until pipeline.stopped?
      end
      pipeline.shutdown
      expect(output.events.map {|e| e.get("message")}).to include("END")
      expect(output.events.size).to eq(2)
      expect(output.events[0].get("tags")).to eq(["notdropped"])
      expect(output.events[1].get("tags")).to eq(["notdropped"])

      Thread.abort_on_exception = abort_on_exception_state
    end
  end

  context "when the output plugin raises an abort batch exception" do
    let(:metric) { LogStash::Instrument::Metric.new(LogStash::Instrument::Collector.new) }
    subject { mock_java_pipeline_from_string(config, pipeline_settings_obj, metric) }
    let(:metric_store) { subject.metric.collector.snapshot_metric.metric_store }
    let(:config) do
      <<-EOS
      input { dummymanualinputgenerator {iterations => 2} }
      output { dummyabortingoutput {} }
      EOS
    end
    let(:dummyabortingoutput) { DummyAbortingOutput.new }
    let(:pipeline_settings) { super().merge({ "pipeline.batch.size" => 2, "queue.type" => "persisted"}) }

    let(:collected_metric) { metric_store.get_with_path("stats/events") }
    let (:queue_client_batch) { double("Acked queue client Mock") }
    let(:logger) { double("pipeline logger").as_null_object }

    before :each do
      # warn: use a real DummyAbortingOutput plugin instantiated by PluginFactory because it needs
      # a properly initialized ExecutionContext, so DONT' mock the constructor of DummyAbortingOutput
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummymanualinputgenerator").and_return(DummyManualInputGenerator)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyabortingoutput").and_return(DummyAbortingOutput)
      allow(LogStash::JavaPipeline).to receive(:filter_queue_client).and_return(queue_client_batch)
      allow(LogStash::JavaPipeline).to receive(:logger).twice.and_return(logger)
    end

   before(:each) do
      expect { subject.start }.to_not raise_error
      expect(queue_client_batch).to_not receive(:close_batch)

      # make sure all the workers are started
      wait(5).for {subject.worker_threads.any?(&:alive?)}.to be_truthy
    end
    it "should not acknowledge the batch" do
      # command a shutdown while the output is processing a batch and not completing it
      thread = Thread.new { subject.shutdown_workers }

      # wait for inputs to terminate
      wait(5).for {subject.input_threads.any?(&:alive?)}.to be_falsey

      # the exception raised by the aborting output should have stopped the workers
      wait(5).for {subject.worker_threads.any?(&:alive?)}.to be_falsey

      # need to wait that the pipeline thread stops completely, else the logger mock could be
      # used outside of this context
      subject.wait_for_shutdown

      # verify the not completed batch by checking output stats
      expect(collected_metric[:stats][:events][:duration_in_millis].value).not_to be_nil
      expect(collected_metric[:stats][:events][:in].value).to eq(2)
      expect(collected_metric[:stats][:events][:out].value).to eq(0)
    end

    it "should not throw a generic error" do
      expect(logger).not_to receive(:error).with(/Pipeline worker error, the pipeline will be stopped/, anything)

      # command a shutdown while the output is processing a batch and not completing it
      thread = Thread.new { subject.shutdown_workers }

      # wait for inputs to terminate
      wait(5).for {subject.input_threads.any?(&:alive?)}.to be_falsey

      # the exception raised by the aborting output should have stopped the workers
      wait(5).for {subject.worker_threads.any?(&:alive?)}.to be_falsey

      # need to wait that the pipeline thread stops completely, else the logger mock could be
      # used outside of this context
      subject.wait_for_shutdown
    end
  end

  context "when logical expression in conditional" do
    extend PipelineHelpers

    let(:settings) { LogStash::SETTINGS.clone }

    config <<-CONFIG
          filter {
            if [path][to][value] > 100 {
              mutate { add_tag => "hit" }
            } else {
              mutate { add_tag => "miss" }
            }
          }
        CONFIG

    context "raise an error when it's evaluated, should cancel the event execution and log the error" do
      context "when type of evaluation doesn't have same type" do
        sample_one( [{ "path" => {"to" => {"value" => "101"}}}] ) do
          expect(subject).to be nil
          expect(pipeline.last_error_evaluation_received).to match(/no implicit conversion of nil into Integer/)
        end
      end

      context "when left and right operands of event condition are not comparable" do
        context "comparing a non existing field" do
          sample_one( [{ "path" => {"to" => "Rome"}}] ) do
            expect(subject).to be nil
            expect(pipeline.last_error_evaluation_received).to match(/<no-class>:<null-value>/)
          end
        end

        context "comparing incompatible types" do
          sample_one( [{ "path" => {"to" => {"value" => [101, 102]}}}] ) do
            expect(subject).to be nil
            expect(pipeline.last_error_evaluation_received).to match(/Unexpected conditional input combination of.*List.*RubyFixnum/)
          end
        end
      end

      context "when the offending logic expression is used in a nested conditional structure" do
        config <<-CONFIG
                  filter {
                    if "a" == "a" {
                      if "b" == "b" {
                        if [path][to][value] > 100 {
                          mutate { add_tag => "hit" }
                        } else {
                          mutate { add_tag => "miss" }
                        }
                      }
                    }
                  }
                CONFIG

        sample_one( [{ "path" => {"to" => {"value" => "101"}}}] ) do
          expect(subject).to be nil
          expect(pipeline.last_error_evaluation_received).to match(/no implicit conversion of nil into Integer/)
        end
      end

      context "when the offending condition is in the output section" do
        before do
          LogStash::PLUGIN_REGISTRY.add(:input, "spec_sampler_input", PipelineHelpers::SpecSamplerInput)
          LogStash::PLUGIN_REGISTRY.add(:output, "spec_sampler_output", PipelineHelpers::SpecSamplerOutput)
        end

        context "given a pipeline executing an event that would trigger an evaluation error" do
          let(:pipeline) do
            LogStash::JavaPipeline.new(
              org.logstash.config.ir.PipelineConfig.new(
                LogStash::Config::Source::Local, :main,
                SourceWithMetadata.new(
                  "config_string", "config_string",
                  "input { spec_sampler_input {} }\n output { if [path][to][value] > 100 { spec_sampler_output {} } }"
                ), settings
              )
            )
          end
          let(:event) do
            [LogStash::Event.new({ "path" => {"to" => {"value" => "101"}}})]
          end

          let(:results) do
            PipelineHelpers::SpecSamplerInput.set_event event
            pipeline.run
            PipelineHelpers::SpecSamplerOutput.seen
          end

          after do
            pipeline.close
          end

          describe "when DLQ is disabled" do
            let(:settings) do
              s = super()
              s.set_value("queue.drain", true)
              s
            end

            subject {results.length > 1 ? results : results.first}

            it "should raise an error without killing the pipeline" do
              expect(subject).to be nil
              expect(pipeline.last_error_evaluation_received).to match(/no implicit conversion of nil into Integer/)
            end
          end

          describe "when DLQ is enabled" do
            let(:dlq_path) { Dir.mktmpdir }

            let(:settings) do
              s = super()
              s.set_value("queue.drain", true)
              s.set_value("pipeline.id", "test_dlq")
              s.set_value("dead_letter_queue.enable", true)
              s.set_value("path.dead_letter_queue", dlq_path)
              s
            end

            after do
              FileUtils.rm_rf(settings.get_value("path.dead_letter_queue"))
            end

            subject {results.length > 1 ? results : results.first}

            it "should raise an error without killing the pipeline and insert the event into DLQ" do
              expect(subject).to be nil
              expect(pipeline.last_error_evaluation_received).to match(/no implicit conversion of nil into Integer/)
              dlq_path = java.nio.file.Paths.get(settings.get_value("path.dead_letter_queue"), "test_dlq")
              dlq_reader = org.logstash.common.io.DeadLetterQueueReader.new(dlq_path)
              entry = dlq_reader.pollEntry(40)
              expect(entry).to_not be_nil
              expect(entry.reason).to match(/condition evaluation error.*no implicit conversion of nil into Integer/)
              expect(entry.plugin_id).to eq("if-statement")
              expect(entry.plugin_type).to eq("if-statement")
            end
          end
        end

        describe "given a pipeline executing an event with invalid UTF-8 string" do
          let(:pipeline) do
            settings.set_value("queue.drain", true)
            LogStash::JavaPipeline.new(
              org.logstash.config.ir.PipelineConfig.new(
                LogStash::Config::Source::Local, :main,
                SourceWithMetadata.new(
                  "config_string", "config_string",
                  "input { spec_sampler_input {} }\n output { if [message] =~ /^(NOSQL|SQL):/ { spec_sampler_output {} } }"
                ), settings
              )
            )
          end
          let(:event) do
            [LogStash::Event.new({ "message" => "abrac\xC5adabra"})]
          end

          let(:results) do
            PipelineHelpers::SpecSamplerInput.set_event event
            pipeline.run
            PipelineHelpers::SpecSamplerOutput.seen
          end

          after do
            pipeline.close
          end

          subject {results.length > 1 ? results : results.first}

          it "should raise an error without killing the pipeline" do
            expect(subject).to be nil
            expect(pipeline.last_error_evaluation_received).to match(/invalid byte sequence in UTF-8/)
          end
        end
      end
    end
  end

  context "a crashing worker terminates the pipeline and all inputs and workers" do
    subject { mock_java_pipeline_from_string(config, pipeline_settings_obj) }
    let(:config) do
      <<-EOS
      input { dummymanualinputgenerator {} }
      filter { dummycrashingfilter {} }
      output { dummyoutput {} }
      EOS
    end
    let(:dummyoutput) { ::LogStash::Outputs::DummyOutput.new }
    let(:dummyinput) { DummyManualInputGenerator.new }

    before :each do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(dummyoutput)
      allow(DummyManualInputGenerator).to receive(:new).with(any_args).and_return(dummyinput)

      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummymanualinputgenerator").and_return(DummyManualInputGenerator)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummycrashingfilter").and_return(DummyCrashingFilter)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
    end

    context "a crashing worker using memory queue" do
      let(:pipeline_settings) { super().merge({ "pipeline.batch.size" => 1, "pipeline.workers" => 1, "queue.type" => "memory"}) }

      it "does not raise in the main thread, terminates the run thread and finishes execution" do
        # first make sure we keep the input plugin in the run method for now
        dummyinput.keep_running.make_true

        expect { subject.start }.to_not raise_error

        # wait until there is no more worker thread since we have a single worker that should have died
        wait(5).for {subject.worker_threads.any?(&:alive?)}.to be_falsey
        expect(subject.crashed?).to be true

        # at this point the input plugin should have been asked to stop
        wait(5).for {dummyinput.stop?}.to be_truthy

        # allow the input plugin to exit the run method now
        dummyinput.keep_running.make_false

        # the pipeline thread should terminate normally
        expect { subject.thread.join }.to_not raise_error
        expect(subject.finished_execution?).to be_truthy

        # when the pipeline has exited, no input threads should be alive
        wait(5).for {subject.input_threads.any?(&:alive?)}.to be_falsey
      end
    end

    context "a crashing worker using persisted queue" do
      let(:pipeline_settings) { super().merge({ "pipeline.batch.size" => 1, "pipeline.workers" => 1, "queue.type" => "persisted"}) }

      it "does not raise in the main thread, terminates the run thread and finishes execution" do
        # first make sure we keep the input plugin in the run method for now
        dummyinput.keep_running.make_true

        expect { subject.start }.to_not raise_error

        # wait until there is no more worker thread since we have a single worker that should have died
        wait(5).for {subject.worker_threads.any?(&:alive?)}.to be_falsey
        expect(subject.crashed?).to be true

        # at this point the input plugin should have been asked to stop
        wait(5).for {dummyinput.stop?}.to be_truthy

        # allow the input plugin to exit the run method now
        dummyinput.keep_running.make_false

        # the pipeline thread should terminate normally
        expect { subject.thread.join }.to_not raise_error
        expect(subject.finished_execution?).to be_truthy

        # when the pipeline has exited, no input threads should be alive
        wait(5).for {subject.input_threads.any?(&:alive?)}.to be_falsey

        expect {dummyinput.push_once}.to raise_error(/Tried to write to a closed queue/)
      end
    end
  end

  describe "defaulting the pipeline workers based on thread safety" do
    before(:each) do
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummyinput").and_return(DummyInput)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(DummyCodec)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummyfilter").and_return(DummyFilter)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummysafefilter").and_return(DummySafeFilter)
    end

    context "when there are some not threadsafe filters" do
      let(:test_config_with_filters) {
        <<-eos
        input {
          dummyinput {}
        }

        filter {
          dummyfilter {}
        }

        output {
          dummyoutput {}
        }
        eos
      }

      describe "debug compiled" do
        let(:logger) { double("pipeline logger").as_null_object }

        before do
          expect(::LogStash::JavaPipeline).to receive(:logger).and_return(logger)
          allow(logger).to receive(:debug?).and_return(true)
        end

        it "should not receive a debug message with the compiled code" do
          pipeline_settings_obj.set("config.debug", false)
          expect(logger).not_to receive(:debug).with(/Compiled pipeline/, anything)
          pipeline = mock_java_pipeline_from_string(test_config_with_filters)
          pipeline.close
        end

        it "should print the compiled code if config.debug is set to true" do
          skip("This test does not work when using a Java Logger and should be ported to JUnit")
          pipeline_settings_obj.set("config.debug", true)
          expect(logger).to receive(:debug).with(/Compiled pipeline/, anything)
          pipeline = mock_java_pipeline_from_string(test_config_with_filters, pipeline_settings_obj)
          pipeline.close
        end
      end

      context "when there is no command line -w N set" do
        it "starts one filter thread" do
          msg = "Defaulting pipeline worker threads to 1 because there are some filters that might not work with multiple worker threads"
          pipeline = mock_java_pipeline_from_string(test_config_with_filters)
          expect(pipeline.logger).to receive(:warn).with(msg,
            hash_including({:count_was => worker_thread_count, :filters => ["dummyfilter"]}))
          pipeline.start
          expect(pipeline.worker_threads.size).to eq(safe_thread_count)
          pipeline.shutdown
        end
      end

      context "when there is command line -w N set" do
        let(:pipeline_settings) { super().merge({"pipeline.workers" => override_thread_count }) }
        it "starts multiple filter thread" do
          msg = "Warning: Manual override - there are filters that might" +
                " not work with multiple worker threads"
          pipeline = mock_java_pipeline_from_string(test_config_with_filters, pipeline_settings_obj)
          expect(pipeline.logger).to receive(:warn).with(msg, hash_including({:worker_threads => override_thread_count, :filters => ["dummyfilter"]}))
          pipeline.start
          expect(pipeline.worker_threads.size).to eq(override_thread_count)
          pipeline.shutdown
        end
      end
    end

    context "when there are threadsafe filters only" do
      let(:test_config_with_filters) {
        <<-eos
        input {
          dummyinput {}
        }

        filter {
          dummysafefilter {}
        }

        output {
          dummyoutput {}
        }
        eos
      }

      it "starts multiple filter threads" do
        skip("This test has been failing periodically since November 2016. Tracked as https://github.com/elastic/logstash/issues/6245")
        pipeline = mock_java_pipeline_from_string(test_config_with_filters)
        pipeline.start
        expect(pipeline.worker_threads.size).to eq(worker_thread_count)
        pipeline.shutdown
      end
    end
  end

  context "close" do
    before(:each) do
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummyinput").and_return(DummyInput)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(DummyCodec)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
    end

    let(:test_config_without_output_workers) {
      <<-eos
      input {
        dummyinput {}
      }

      output {
        dummyoutput {}
      }
      eos
    }

    let(:test_config_with_output_workers) {
      <<-eos
      input {
        dummyinput {}
      }

      output {
        dummyoutput {
          workers => 2
        }
      }
      eos
    }

    context "input and output close" do
      let(:pipeline) { mock_java_pipeline_from_string(test_config_without_output_workers) }
      let(:output) { pipeline.outputs.first }
      let(:input) { pipeline.inputs.first }

      it "should call close of input and output without output-workers" do
        expect(output).to receive(:do_close).once
        expect(input).to receive(:do_close).once
        pipeline.start
        pipeline.shutdown
        expect(pipeline.crashed?).to be false
      end
    end
  end

  context "with no explicit ids declared" do
    before(:each) do
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummyinput").and_return(DummyInput)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(DummyCodec)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummyfilter").and_return(DummyFilter)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
    end

    let(:config) { "input { dummyinput { codec => plain { format => 'something'  } } } filter { dummyfilter {} } output { dummyoutput {} }"}
    let(:pipeline) { mock_java_pipeline_from_string(config) }

    after do
      # If you don't start/stop the pipeline it won't release the queue lock and will
      # cause the suite to fail :(
      pipeline.close
    end

    it "should use LIR provided IDs" do
      expect(pipeline.inputs.first.id).to eq(pipeline.lir.input_plugin_vertices.first.id)
      expect(pipeline.filters.first.id).to eq(pipeline.lir.filter_plugin_vertices.first.id)
      expect(pipeline.outputs.first.id).to eq(pipeline.lir.output_plugin_vertices.first.id)
    end
  end

  context "compiled flush function" do
    extend PipelineHelpers
    let(:settings) { LogStash::SETTINGS.clone }

    describe "flusher thread" do
      before(:each) do
        allow(LogStash::Plugin).to receive(:lookup).with("input", "dummyinput").and_return(DummyInput)
        allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(DummyCodec)
        allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
      end

      let(:config) { "input { dummyinput {} } output { dummyoutput {} }"}

      it "should start the flusher thread only after the pipeline is running" do
        pipeline = mock_java_pipeline_from_string(config)

        expect(pipeline).to receive(:transition_to_running).ordered.and_call_original
        expect(pipeline).to receive(:start_flusher).ordered.and_call_original

        pipeline.start
        pipeline.shutdown
      end
    end

    context "cancelled events should not propagate down the filters" do
      config <<-CONFIG
        filter {
          drop {}
        }
      CONFIG

      sample_one("hello") do
        expect(subject).to eq(nil)
      end
    end

    context "new events should propagate down the filters" do
      config <<-CONFIG
        filter {
          clone {
            clones => ["clone1"]
          }
        }
      CONFIG

      sample_one(["foo", "bar"]) do
        expect(subject.size).to eq(4)
      end
    end
  end

  context "batch order" do
    extend PipelineHelpers

    context "with a single worker and ordering enabled" do
      let(:settings) do
        s = LogStash::SETTINGS.clone
        s.set_value("pipeline.workers", 1)
        s.set_value("pipeline.ordered", "true")
        s
      end

      config <<-CONFIG
        filter {
          if [message] =~ "\\d" {
            mutate { add_tag => "digit" }
          } else {
            mutate { add_tag => "letter" }
          }
        }
      CONFIG

       sample_one(["a", "1", "b", "2", "c", "3"]) do
        expect(subject.map {|e| e.get("message")}).to eq(["a", "1", "b", "2", "c", "3"])
      end
    end

    context "with a multiple workers and ordering enabled" do
      let(:settings) do
        s = LogStash::SETTINGS.clone
        s.set_value("pipeline.workers", 2)
        s.set_value("pipeline.ordered", "true")
        s
      end
      let(:config) { "input { } output { }" }
      let(:pipeline) { mock_java_pipeline_from_string(config, settings) }

      it "should raise error" do
        expect {pipeline.run}.to raise_error(RuntimeError, /pipeline\.ordered/)
        pipeline.close
      end
    end

    context "with an explicit single worker ordering will auto enable" do
      let(:settings) do
        s = LogStash::SETTINGS.clone
        s.set_value("pipeline.workers", 1)
        s.set_value("pipeline.ordered", "auto")
        s
      end

      config <<-CONFIG
        filter {
          if [message] =~ "\\d" {
            mutate { add_tag => "digit" }
          } else {
            mutate { add_tag => "letter" }
          }
        }
      CONFIG

       sample_one(["a", "1", "b", "2", "c", "3"]) do
        expect(subject.map {|e| e.get("message")}).to eq(["a", "1", "b", "2", "c", "3"])
      end
    end

    context "with an implicit single worker ordering will not auto enable" do
      let(:settings) do
        s = LogStash::SETTINGS.clone
        s.set_value("pipeline.ordered", "auto")
        s
      end

      before(:each) do
        # this is to make sure this test will be valid by having a pipeline.workers default value > 1
        # and not explicitly set.
        expect(settings.get_default("pipeline.workers")).to be > 1
        expect(settings.set?("pipeline.workers")).to be_falsey

        expect(LogStash::Plugin).to receive(:lookup).with("filter", "dummyfilter").at_least(1).time.and_return(DummyFilter)
        expect(LogStash::Plugin).to receive(:lookup).with(any_args).at_least(3).time.and_call_original
      end

      config <<-CONFIG
        filter {
          # per above dummyfilter is not threadsafe hence will set the number of workers to 1
          dummyfilter { }

          if [message] =~ "\\d" {
            mutate { add_tag => "digit" }
          } else {
            mutate { add_tag => "letter" }
          }
        }
      CONFIG

      sample_one(["a", "1", "b", "2", "c", "3"]) do
        expect(subject.map {|e| e.get("message")}).to eq(["1", "2", "3", "a", "b", "c"])
      end
    end

    context "with a single worker and ordering disabled" do
      let(:settings) do
        s = LogStash::SETTINGS.clone
        s.set_value("pipeline.workers", 1)
        s.set_value("pipeline.ordered", "false")
        s
      end

      config <<-CONFIG
        filter {
          if [message] =~ "\\d" {
            mutate { add_tag => "digit" }
          } else {
            mutate { add_tag => "letter" }
          }
        }
      CONFIG

      sample_one(["a", "1", "b", "2", "c", "3"]) do
        expect(subject.map {|e| e.get("message")}).to eq(["1", "2", "3", "a", "b", "c"])
      end
    end
  end

  describe "max inflight warning" do
    let(:config) { "input { dummyinput {} } output { dummyoutput {} }" }
    let(:batch_size) { 1 }
    let(:pipeline_settings) { super().merge({ "pipeline.batch.size" => batch_size, "pipeline.workers" => 1 }) }
    let(:pipeline) { mock_java_pipeline_from_string(config, pipeline_settings_obj) }
    let(:logger) { pipeline.logger }
    let(:warning_prefix) { Regexp.new("CAUTION: Recommended inflight events max exceeded!") }

    before(:each) do
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummyinput").and_return(DummyInput)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(DummyCodec)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
      allow(logger).to receive(:warn)

      pipeline.start
      # the only input auto-closes, so the pipeline will automatically stop.
      sleep(0.01) until pipeline.stopped?
      pipeline.shutdown
    end

    it "should not raise a max inflight warning if the max_inflight count isn't exceeded" do
      expect(logger).not_to have_received(:warn).with(warning_prefix)
    end

  end

  context "compiled filter functions" do
    context "new events should propagate down the filters" do
      extend PipelineHelpers
      let(:settings) { LogStash::SETTINGS.clone }

      config <<-CONFIG
        filter {
          clone {
            ecs_compatibility => disabled
            clones => ["clone1", "clone2"]
          }
          mutate {
            add_field => {"foo" => "bar"}
          }
        }
      CONFIG

      sample_one("hello") do
        expect(subject.size).to eq(3)

        expect(subject[0].get("message")).to eq("hello")
        expect(subject[0].get("type")).to be_nil
        expect(subject[0].get("foo")).to eq("bar")

        expect(subject[1].get("message")).to eq("hello")
        expect(subject[1].get("type")).to eq("clone1")
        expect(subject[1].get("foo")).to eq("bar")

        expect(subject[2].get("message")).to eq("hello")
        expect(subject[2].get("type")).to eq("clone2")
        expect(subject[2].get("foo")).to eq("bar")
      end
    end
  end

  context "metrics" do
    config = "input { } filter { } output { }"

    let(:settings) { LogStash::SETTINGS.clone }
    subject { mock_java_pipeline_from_string(config, settings, metric) }

    after :each do
      subject.close
    end

    context "when metric.collect is disabled" do
      before :each do
        settings.set("metric.collect", false)
      end

      context "if namespaced_metric is nil" do
        let(:metric) { nil }
        it "uses a `NullMetric` object" do
          expect(subject.metric).to be_a(LogStash::Instrument::NullMetric)
        end
      end

      context "if namespaced_metric is a Metric object" do
        let(:collector) { ::LogStash::Instrument::Collector.new }
        let(:metric) { ::LogStash::Instrument::Metric.new(collector) }

        it "uses a `NullMetric` object" do
          expect(subject.metric).to be_a(LogStash::Instrument::NullMetric)
        end

        it "uses the same collector" do
          expect(subject.metric.collector).to be(collector)
        end
      end

      context "if namespaced_metric is a NullMetric object" do
        let(:collector) { ::LogStash::Instrument::Collector.new }
        let(:metric) { ::LogStash::Instrument::NullMetric.new(collector) }

        it "uses a `NullMetric` object" do
          expect(subject.metric).to be_a(::LogStash::Instrument::NullMetric)
        end

        it "uses the same collector" do
          expect(subject.metric.collector).to be(collector)
        end
      end
    end

    context "when metric.collect is enabled" do
      before :each do
        settings.set("metric.collect", true)
      end

      context "if namespaced_metric is nil" do
        let(:metric) { nil }
        it "uses a `NullMetric` object" do
          expect(subject.metric).to be_a(LogStash::Instrument::NullMetric)
        end
      end

      context "if namespaced_metric is a Metric object" do
        let(:collector) { ::LogStash::Instrument::Collector.new }
        let(:metric) { ::LogStash::Instrument::Metric.new(collector) }

        it "uses a `Metric` object" do
          expect(subject.metric).to be_a(LogStash::Instrument::Metric)
        end

        it "uses the same collector" do
          expect(subject.metric.collector).to be(collector)
        end
      end

      context "if namespaced_metric is a NullMetric object" do
        let(:collector) { ::LogStash::Instrument::Collector.new }
        let(:metric) { ::LogStash::Instrument::NullMetric.new(collector) }

        it "uses a `NullMetric` object" do
          expect(subject.metric).to be_a(LogStash::Instrument::NullMetric)
        end

        it "uses the same collector" do
          expect(subject.metric.collector).to be(collector)
        end
      end
    end
  end

  context "Periodic Flush" do
    shared_examples 'it flushes correctly' do
      let(:config) do
        <<-EOS
      input {
        dummy_input {}
      }
      filter {
        dummy_flushing_filter {}
      }
      output {
        dummy_output {}
      }
        EOS
      end
      let(:output) { ::LogStash::Outputs::DummyOutput.new }

      before do
        allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(output)
        allow(LogStash::Plugin).to receive(:lookup).with("input", "dummy_input").and_return(LogStash::Inputs::DummyBlockingInput)
        allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummy_flushing_filter").and_return(DummyFlushingFilterPeriodic)
        allow(LogStash::Plugin).to receive(:lookup).with("output", "dummy_output").and_return(::LogStash::Outputs::DummyOutput)
        allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
      end

      it "flush periodically" do
        Thread.abort_on_exception = true
        pipeline = mock_java_pipeline_from_string(config, pipeline_settings_obj)
        Timeout.timeout(timeout) do
          pipeline.start
        end
        Stud.try(max_retry.times, [StandardError, RSpec::Expectations::ExpectationNotMetError]) do
          wait(10).for do
            # give us a bit of time to flush the events
            output.events.empty?
          end.to be_falsey
        end

        expect(output.events.any? {|e| e.get("message") == "dummy_flush"}).to eq(true)

        pipeline.shutdown
      end
    end

    it_behaves_like 'it flushes correctly'

    context 'with pipeline ordered' do
      before do
        pipeline_settings_obj.set("pipeline.workers", 1)
        pipeline_settings_obj.set("pipeline.ordered", true)
      end
      it_behaves_like 'it flushes correctly'
    end
  end
  context "Pipeline created with too many filters" do
    # create pipeline with 2000 filters
    # 2000 filters is more than a thread stack of size 2MB can handle
    let(:config) do
      <<-EOS
      input { dummy_input {} }
      filter {
        #{"          nil_flushing_filter {}\n" * 2000}
      }
      output { dummy_output {} }
      EOS
    end
    let(:output) { ::LogStash::Outputs::DummyOutput.new }

    before do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(output)
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummy_input").and_return(LogStash::Inputs::DummyBlockingInput)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "nil_flushing_filter").and_return(NilFlushingFilterPeriodic)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummy_output").and_return(::LogStash::Outputs::DummyOutput)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
    end

    let(:pipeline) { mock_java_pipeline_from_string(config, pipeline_settings_obj) }

    it "informs the user that a stack overflow occurred" do
      allow(pipeline.logger).to receive(:error)

      pipeline.start
      pipeline.shutdown

      expect(pipeline.logger).to have_received(:error).with(/Stack overflow/, anything).at_least(:once)
    end
  end
  context "Periodic Flush that intermittently returns nil" do
    let(:config) do
      <<-EOS
      input {
        dummy_input {}
      }
      filter {
        nil_flushing_filter {}
      }
      output {
        dummy_output {}
      }
      EOS
    end
    let(:output) { ::LogStash::Outputs::DummyOutput.new }

    before do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(output)
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummy_input").and_return(LogStash::Inputs::DummyBlockingInput)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "nil_flushing_filter").and_return(NilFlushingFilterPeriodic)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummy_output").and_return(::LogStash::Outputs::DummyOutput)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
    end

    it "flush periodically without error on nil flush return" do
      Thread.abort_on_exception = true
      pipeline = mock_java_pipeline_from_string(config, pipeline_settings_obj)
      Timeout.timeout(timeout) do
        pipeline.start
      end
      Stud.try(max_retry.times, [StandardError, RSpec::Expectations::ExpectationNotMetError]) do
        wait(10).for do
          # give us a bit of time to flush the events
          output.events.empty?
        end.to be_falsey
      end

      expect(output.events.any? {|e| e.get("message") == "dummy_flush"}).to eq(true)

      pipeline.shutdown
    end
  end

  context "Periodic Flush Wrapped in Nested Conditional" do
    let(:config) do
      <<-EOS
      input {
        dummy_input {}
      }
      filter {
        if [type] == "foo" {
          if [@bar] {
             dummy_flushing_filter {}
          }
        } else {
          drop {}
        }
      }
      output {
        dummy_output {}
      }
      EOS
    end
    let(:output) { ::LogStash::Outputs::DummyOutput.new }

    before do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(output)
      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummy_input").and_return(LogStash::Inputs::DummyBlockingInput)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummy_flushing_filter").and_return(DummyFlushingFilterPeriodic)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummy_output").and_return(::LogStash::Outputs::DummyOutput)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "drop").and_call_original
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
    end

    it "flush periodically" do
      Thread.abort_on_exception = true
      pipeline = mock_java_pipeline_from_string(config, pipeline_settings_obj)
      Timeout.timeout(timeout) do
        pipeline.start
      end
      Stud.try(max_retry.times, [StandardError, RSpec::Expectations::ExpectationNotMetError]) do
        wait(11).for do
          # give us a bit of time to flush the events
          output.events.size >= 2
        end.to be_truthy
      end

      expect(output.events.any? {|e| e.get("message") == "dummy_flush"}).to eq(true)

      pipeline.shutdown
    end
  end

  context "with multiple outputs" do
    let(:config) do
      <<-EOS
      input {
        generator { count => 10 }
      }
      filter {
       clone {
          add_field => {
            'cloned' =>  'cloned'
          }
          clones => ["clone1"]
        }
      }
      output {
        dummy_output {}
        dummy_output {}
        dummy_output {}
      }
      EOS
    end
    let(:output) { ::LogStash::Outputs::DummyOutput.new }

    before do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(output)
      allow(LogStash::Plugin).to receive(:lookup).with("input", "generator").and_call_original
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "clone").and_call_original
      3.times {
        allow(LogStash::Plugin).to receive(:lookup).with("output", "dummy_output").and_return(::LogStash::Outputs::DummyOutput)
        allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
      }
    end

    it "correctly distributes events" do
      pipeline = mock_java_pipeline_from_string(config, pipeline_settings_obj)
      pipeline.start
      sleep 0.01 until pipeline.finished_execution?
      pipeline.shutdown
      expect(output.events.size).to eq(60)
      expect(output.events.count {|e| e.get("cloned") == "cloned"}).to eq(30)
    end
  end

  context "#started_at" do
    # use a run limiting count to shutdown the pipeline automatically
    let(:config) do
      <<-EOS
      input {
        generator { count => 10 }
      }
      EOS
    end

    subject { mock_java_pipeline_from_string(config) }

    context "when the pipeline is not started" do
      after :each do
        subject.close
      end

      it "returns nil when the pipeline isnt started" do
        expect(subject.started_at).to be_nil
      end
    end

    it "return when the pipeline started working" do
      subject.start
      expect(subject.started_at).to be < Time.now
      subject.shutdown
    end
  end

  context "#uptime" do
    let(:config) do
      <<-EOS
      input {
        generator {}
      }
      EOS
    end
    subject { mock_java_pipeline_from_string(config) }

    context "when the pipeline is not started" do
      after :each do
        subject.close
      end

      it "returns 0" do
        expect(subject.uptime).to eq(0)
      end
    end

    context "when the pipeline is started" do
      it "return the duration in milliseconds" do
        Timeout.timeout(timeout) do
          subject.start
        end
        sleep(0.1)
        expect(subject.uptime).to be > 0
        subject.shutdown
      end
    end
  end

  context "when collecting metrics in the pipeline" do
    let(:metric) { LogStash::Instrument::Metric.new(LogStash::Instrument::Collector.new) }

    subject { mock_java_pipeline_from_string(config, pipeline_settings_obj, metric) }

    let(:pipeline_settings) { super().merge({ "pipeline.id" => pipeline_id }) }
    let(:pipeline_id) { "main" }
    let(:number_of_events) { 420 }
    let(:dummy_id) { "my-multiline" }
    let(:dummy_id_other) { "my-multiline_other" }
    let(:dummy_output_id) { "my-dummyoutput" }
    let(:generator_id) { "my-generator" }
    let(:config) do
      <<-EOS
      input {
        generator {
           count => #{number_of_events}
           id => "#{generator_id}"
        }
      }
      filter {
          dummyfilter {
              id => "#{dummy_id}"
          }
          dummyfilter {
               id => "#{dummy_id_other}"
           }
      }
      output {
        dummyoutput {
          id => "#{dummy_output_id}"
        }
      }
      EOS
    end
    let(:dummyoutput) { ::LogStash::Outputs::DummyOutput.new({ "id" => dummy_output_id }) }
    let(:metric_store) { subject.metric.collector.snapshot_metric.metric_store }

    before :each do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(dummyoutput)
      allow(LogStash::Plugin).to receive(:lookup).with("input", "generator").and_return(LogStash::Inputs::Generator)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummyfilter").and_return(LogStash::Filters::DummyFilter)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)

      Timeout.timeout(timeout) do
        subject.start
      end

      # make sure we have received all the generated events
      Stud.try(max_retry.times, [StandardError, RSpec::Expectations::ExpectationNotMetError]) do
        wait(3).for do
          # give us a bit of time to flush the events
          dummyoutput.events.size >= number_of_events
        end.to be_truthy
      end
    end

    after :each do
      subject.shutdown
    end

    context "global metric" do
      let(:collected_metric) { metric_store.get_with_path("stats/events") }

      it "populates the different metrics" do
        expect(collected_metric[:stats][:events][:duration_in_millis].value).not_to be_nil
        expect(collected_metric[:stats][:events][:in].value).to eq(number_of_events)
        expect(collected_metric[:stats][:events][:filtered].value).to eq(number_of_events)
        expect(collected_metric[:stats][:events][:out].value).to eq(number_of_events)
      end
    end

    context "pipelines" do
      let(:collected_metric) { metric_store.get_with_path("stats/pipelines/") }

      it "populates the pipelines core metrics" do
        expect(collected_metric[:stats][:pipelines][:main][:events][:duration_in_millis].value).not_to be_nil
        expect(collected_metric[:stats][:pipelines][:main][:events][:in].value).to eq(number_of_events)
        expect(collected_metric[:stats][:pipelines][:main][:events][:filtered].value).to eq(number_of_events)
        expect(collected_metric[:stats][:pipelines][:main][:events][:out].value).to eq(number_of_events)
      end

      it "populates the filter metrics" do
        [dummy_id, dummy_id_other].map(&:to_sym).each do |id|
          [:in, :out].each do |metric_key|
            plugin_name = id.to_sym
            expect(collected_metric[:stats][:pipelines][:main][:plugins][:filters][plugin_name][:events][metric_key].value).to eq(number_of_events)
          end
        end
      end

      it "populates the output metrics" do
        plugin_name = dummy_output_id.to_sym

        expect(collected_metric[:stats][:pipelines][:main][:plugins][:outputs][plugin_name][:events][:in].value).to eq(number_of_events)
        expect(collected_metric[:stats][:pipelines][:main][:plugins][:outputs][plugin_name][:events][:out].value).to eq(number_of_events)
        expect(collected_metric[:stats][:pipelines][:main][:plugins][:outputs][plugin_name][:events][:duration_in_millis].value).not_to be_nil
      end

      it "populates the name of the output plugin" do
        plugin_name = dummy_output_id.to_sym
        expect(collected_metric[:stats][:pipelines][:main][:plugins][:outputs][plugin_name][:name].value).to eq(::LogStash::Outputs::DummyOutput.config_name)
      end

      it "populates the name of the filter plugin" do
        [dummy_id, dummy_id_other].map(&:to_sym).each do |id|
          plugin_name = id.to_sym
          expect(collected_metric[:stats][:pipelines][:main][:plugins][:filters][plugin_name][:name].value).to eq(LogStash::Filters::DummyFilter.config_name)
        end
      end

      context 'when dlq is disabled' do
        let (:collect_stats) { subject.collect_dlq_stats}
        let (:collected_stats) { collected_metric[:stats][:pipelines][:main][:dlq]}
        let (:available_stats) {[:path, :queue_size_in_bytes]}

        it 'should show not show any dlq stats' do
          collect_stats
          expect(collected_stats).to be_nil
        end
      end

      context 'when dlq is enabled' do
        let (:dead_letter_queue_enabled) { true }
        let (:dead_letter_queue_path) { Stud::Temporary.directory }
        let (:pipeline_dlq_path) { "#{dead_letter_queue_path}/#{pipeline_id}"}

        let (:collect_stats) { subject.collect_dlq_stats }
        let (:collected_stats) { collected_metric[:stats][:pipelines][:main][:dlq]}

        it 'should show dlq stats' do
          collect_stats
          # A newly created dead letter queue with no entries will have a size of 1 (the version 'header')
          expect(collected_stats[:queue_size_in_bytes].value).to eq(1)
          expect(collected_stats[:storage_policy].value).to eq("drop_newer")
        end
      end
    end
  end

  context "Pipeline object" do
    before do
      allow(LogStash::Plugin).to receive(:lookup).with("input", "generator").and_return(LogStash::Inputs::Generator)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(DummyCodec)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummyfilter").and_return(DummyFilter)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
    end

    let(:pipeline1) { mock_java_pipeline_from_string("input { generator {} } filter { dummyfilter {} } output { dummyoutput {}}") }
    let(:pipeline2) { mock_java_pipeline_from_string("input { generator {} } filter { dummyfilter {} } output { dummyoutput {}}") }

    # multiple pipelines cannot be instantiated using the same PQ settings, force memory queue
    before :each do
      pipeline_workers_setting = LogStash::SETTINGS.get_setting("queue.type")
      allow(pipeline_workers_setting).to receive(:value).and_return("memory")
      pipeline_settings.each {|k, v| pipeline_settings_obj.set(k, v) }
    end

    it "should not add ivars" do
       expect(pipeline1.instance_variables).to eq(pipeline2.instance_variables)
    end
  end

  context "#system" do
    after do
      pipeline.close # close the queue
    end

    context "when the pipeline is a system pipeline" do
      let(:pipeline) { mock_java_pipeline_from_string("input { generator {} } output { null {} }", mock_settings("pipeline.system" => true)) }
      it "returns true" do
        expect(pipeline.system?).to be_truthy
      end
    end

    context "when the pipeline is not a system pipeline" do
      let(:pipeline) { mock_java_pipeline_from_string("input { generator {} } output { null {} }", mock_settings("pipeline.system" => false)) }
      it "returns true" do
        expect(pipeline.system?).to be_falsey
      end
    end
  end

  context "#reloadable?" do
    after do
      pipeline.close # close the queue
    end

    context "when all plugins are reloadable and pipeline is configured as reloadable" do
      let(:pipeline) { mock_java_pipeline_from_string("input { generator {} } output { null {} }", mock_settings("pipeline.reloadable" => true)) }

      it "returns true" do
        expect(pipeline.reloadable?).to be_truthy
      end
    end

    context "when the plugins are not reloadable and pipeline is configured as reloadable" do
      let(:pipeline) { mock_java_pipeline_from_string("input { stdin {} } output { null {} }", mock_settings("pipeline.reloadable" => true)) }

      it "returns true" do
        expect(pipeline.reloadable?).to be_falsey
      end
    end

    context "when all plugins are reloadable and pipeline is configured as non-reloadable" do
      let(:pipeline) { mock_java_pipeline_from_string("input { generator {} } output { null {} }", mock_settings("pipeline.reloadable" => false)) }

      it "returns true" do
        expect(pipeline.reloadable?).to be_falsey
      end
    end
  end

  context "#shutdown" do
    subject(:pipeline) { mock_java_pipeline_from_string(config, pipeline_settings_obj, pipeline_metric) }
    let(:pipeline_metric) { LogStash::Instrument::Metric.new(LogStash::Instrument::Collector.new) }
    let(:dummyinput_class) { DummyManualInputGenerator }
    let(:dummyinput_config) { {'enable_metric' => true} }
    let(:dummyinput) { dummyinput_class.new(dummyinput_config) }
    let(:pipeline_id) { "shutdown" }
    let(:config) { build_pipeline_string_config(dummyinput_config) }

    def build_pipeline_string_config(dummyinput_config)
      <<-"EOS"
      input { dummyinput { #{ dummyinput_config.to_s.tr('{},', '') } } }
      filter { dummyfilter {} }
      output { dummyoutput {} }
      EOS
    end

    before(:each) do
      allow(::LogStash::Outputs::DummyOutput).to receive(:new).with(any_args).and_return(::LogStash::Outputs::DummyOutput::new)
      allow(DummyManualInputGenerator).to receive(:new).with(any_args).and_return(dummyinput)

      allow(LogStash::Plugin).to receive(:lookup).with("input", "dummyinput").and_return(dummyinput_class)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_return(LogStash::Codecs::Plain)
      allow(LogStash::Plugin).to receive(:lookup).with("filter", "dummyfilter").and_return(DummyFilter)
      allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)

      allow(pipeline).to receive(:clear_pipeline_metrics).and_call_original
      allow(pipeline).to receive(:stop_inputs).and_call_original
      allow(pipeline).to receive(:wait_for_shutdown).and_return(double(new: nil))
    end

    context "of a running pipeline" do
      let(:pipeline_settings) { { "pipeline.batch.size" => 1, "pipeline.workers" => 1, "pipeline.id" => pipeline_id, "metric.collect" => true } }

      it "should clear the pipeline metrics" do
        dummyinput.keep_running.make_true

        expect { pipeline.start }.to_not raise_error

        pipeline.shutdown

        expect(pipeline).to have_received(:clear_pipeline_metrics)
        expect(pipeline).to have_received(:stop_inputs)
        expect(pipeline).to have_received(:wait_for_shutdown)
      end
    end

    context "of a failed reloading pipeline" do
      let(:agent) { double("agent") }
      let(:dummyinput_class) { DummyCrashingInput }
      let(:pipeline_settings) { {
        "pipeline.id" => pipeline_id,
        "pipeline.batch.size" => 1,
        "pipeline.workers" => 1,
        "metric.collect" => true,
        "config.reload.automatic" => true
      } }
      let(:pipelines) do
        registry = LogStash::PipelinesRegistry.new
        registry.create_pipeline(pipeline_id.to_sym, pipeline) { true }
        registry
      end

      # This test ensure that even for failed pipeline reloads, the shutdown method cleans
      # the pipeline's metric store. If those metrics are not cleaned, it would pilling up
      # data from previous reloads attempts.
      it "should clear the pipeline metrics for every shutdown" do
        expect { pipeline.start }.to_not raise_error

        wait(10).for { pipeline.running? }

        new_config_string = build_pipeline_string_config({'on_register' => 'true' })
        reload_action = LogStash::PipelineAction::Reload.new(
          mock_pipeline_config(pipeline_id, new_config_string, pipeline_settings),
          pipeline_metric
        )

        # 1st failed attempt (finished_execution? = > false)
        action_result = reload_action.execute(agent, pipelines)
        expect(action_result.successful?).to be_falsy
        expect(pipeline).to have_received(:clear_pipeline_metrics)
        expect(pipeline).to have_received(:stop_inputs)
        expect(pipeline).to have_received(:wait_for_shutdown)

        # 2nd failed attempt (finished_execution? = > true, as the previous reload failed)
        pipeline = pipelines.states.get(pipeline_id.to_sym).pipeline
        allow(pipeline).to receive(:wait_for_shutdown).and_return(double(new: nil))
        allow(pipeline).to receive(:clear_pipeline_metrics).and_call_original

        action_result = reload_action.execute(agent, pipelines)
        expect(action_result.successful?).to be_falsy
        expect(pipeline).to have_received(:clear_pipeline_metrics)
      end
    end
  end
end
