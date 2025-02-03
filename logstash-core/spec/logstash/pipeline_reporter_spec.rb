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
require "logstash/pipeline"
require_relative "../support/helpers"
require_relative "../support/mocks_classes"

#TODO: Figure out how to add more tests that actually cover inflight events
#This will require some janky multithreading stuff
shared_examples "a pipeline reporter" do |pipeline_setup|
  let(:generator_count) { 5 }
  let(:config) do
    "input { generator { count => #{generator_count} } } output { dummyoutput {} } "
  end
  let(:pipeline) { Kernel.send(pipeline_setup, config)}
  let(:reporter) { pipeline.reporter }

  let(:do_setup_plugin_registry) do
    allow(LogStash::Plugin).to receive(:lookup).with("output", "dummyoutput").and_return(::LogStash::Outputs::DummyOutput)
    allow(LogStash::Plugin).to receive(:lookup).with("input", "generator").and_call_original
    allow(LogStash::Plugin).to receive(:lookup).with("codec", "plain").and_call_original
  end

  before do
    do_setup_plugin_registry

    @pre_snapshot = reporter.snapshot

    pipeline.start
    # wait for stopped? so the input can produce all events
    sleep 0.01 until pipeline.stopped?
    pipeline.shutdown
    @post_snapshot = reporter.snapshot
  end

  describe "stalling threads info" do
    it "should start with no stalled threads" do
      expect(@pre_snapshot.stalling_threads_info).to eql([])
    end

    it "should end with no plugin stalled threads" do
      expect(@post_snapshot.stalling_threads_info.length).to be(1)
      expect(@post_snapshot.stalling_threads_info).to include(hash_including("name" => pipeline.instance_variable_get("@thread")[:name]))
    end
  end

  describe "events filtered" do
    it "should start at zero" do
      expect(@pre_snapshot.events_filtered).to eql(0)
    end

    it "should end at the number of generated events" do
      expect(@post_snapshot.events_filtered).to eql(generator_count)
    end
  end

  describe "events consumed" do
    it "should start at zero" do
      expect(@pre_snapshot.events_consumed).to eql(0)
    end

    it "should end at the number of generated events" do
      expect(@post_snapshot.events_consumed).to eql(generator_count)
    end
  end

  describe "inflight count" do
    it "should be zero before running" do
      expect(@pre_snapshot.inflight_count).to eql(0)
    end

    it "should be zero after running" do
      expect(@post_snapshot.inflight_count).to eql(0)
    end

    # We provide a hooked filter that captures a new reporter snapshot with each event.
    # Since the event being processed is by-definition part of a batch that is in-flight,
    # we expect all of the resulting reporter snapshots to have non-zero inflight_event-s
    context "while running" do
      let!(:report_queue) { Queue.new }
      let(:hooked_dummy_filter_class) do
        ::LogStash::Filters::DummyFilter.with_hook do |event|
          report_queue << reporter.snapshot
        end
      end
      let(:hooked_dummy_filter_name) { hooked_dummy_filter_class.config_name }

      let(:config) do
        <<~EOCONFIG
          input  { generator { count => #{generator_count} } }
          filter { #{hooked_dummy_filter_name} {} }
          output { dummyoutput {} }
        EOCONFIG
      end

      let(:do_setup_plugin_registry) do
        super()
        allow(LogStash::Plugin).to receive(:lookup).with("filter", hooked_dummy_filter_name)
                                                   .and_return(hooked_dummy_filter_class)
      end

      it 'captures inflight counts that are non-zero ' do
        inflight_reports = Array.new(report_queue.size) { report_queue.pop }

        expect(inflight_reports).to_not be_empty
        expect(inflight_reports).to all(have_attributes(inflight_count: (a_value > 0)))
      end
    end
  end
end

describe LogStash::PipelineReporter do
  context "with ruby execution" do
    it_behaves_like "a pipeline reporter", :mock_pipeline_from_string
  end
  context "with java execution" do
    it_behaves_like "a pipeline reporter", :mock_java_pipeline_from_string
  end
end
