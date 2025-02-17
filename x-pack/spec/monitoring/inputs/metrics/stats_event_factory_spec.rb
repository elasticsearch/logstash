# Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License;
# you may not use this file except in compliance with the Elastic License.

require "logstash/agent"
require "logstash/runner"
require "spec_helper"
require "monitoring/inputs/metrics/stats_event_factory"
require "logstash/config/pipeline_config"
require 'json'
require "json-schema"

shared_examples_for("old model monitoring event with webserver setting") do
  let(:schema_file) { File.join(schemas_path, "monitoring_document_schema.json") }

  it "should be valid" do
    global_stats = {"uuid" => "00001" }
    sut = described_class.new(global_stats, collector.snapshot_metric, nil)
    LogStash::SETTINGS.set_value("monitoring.enabled", false)
    LogStash::SETTINGS.set_value("api.enabled", webserver_enabled)

    monitoring_evt = sut.make(agent, true)
    json = JSON.parse(monitoring_evt.to_json)
    expect(JSON::Validator.fully_validate(schema_file, monitoring_evt.to_json)).to be_empty
  end
end

shared_examples_for("new model monitoring event with webserver setting") do
  let(:schema_file) { File.join(schemas_path, "monitoring_document_new_schema.json") }

  it "should be valid" do
    global_stats = {"uuid" => "00001" }
    sut = described_class.new(global_stats, collector.snapshot_metric, "funky_cluster_uuid")
    LogStash::SETTINGS.set_value("monitoring.enabled", true)
    LogStash::SETTINGS.set_value("api.enabled", webserver_enabled)

    monitoring_evt = sut.make(agent, true)
    json = JSON.parse(monitoring_evt.to_json)
    expect(json['type']).to eq('logstash_stats')
    expect(JSON::Validator.fully_validate(schema_file, monitoring_evt.to_json)).to be_empty
  end
end

describe LogStash::Inputs::Metrics::StatsEventFactory do
  let(:schemas_path) { File.join(File.dirname(__FILE__), "..", "..", "..", "..", "spec", "monitoring", "schemas") }
  let(:queue) { Concurrent::Array.new }

  let(:config) { "input { dummyblockinginput { } } output { null { } }" }

  let(:pipeline_settings) { LogStash::Runner::SYSTEM_SETTINGS.clone.merge({
    "pipeline.id" => "main",
    "config.string" => config,
    "api.enabled" => webserver_enabled,
  }) }

  let(:agent) { LogStash::Agent.new(pipeline_settings) }
  let(:metric) { agent.metric }
  let(:collector) { metric.collector }
  let(:agent_task) { start_agent(agent) }

  before :each do
    @existing_api_enabled = LogStash::SETTINGS.get_value("api.enabled")
    LogStash::SETTINGS.set_value("api.enabled", webserver_enabled)
    agent
    agent_task

    wait(60).for do
      pipeline = agent.get_pipeline(:main)
      pipeline && pipeline.running?
    end.to be_truthy

    # collector.snapshot_metric is timing dependant and if fired too fast will miss some metrics.
    # after some tests a correct metric_store.size is 72 but when it is incomplete it is lower.
    # I guess this 72 is dependant on the metrics we collect and there is probably a better
    # way to make sure no metrics are missing without forcing a hard sleep but this is what is
    # easily observable, feel free to refactor with a better "timing" test here.
    wait(60).for { collector.snapshot_metric.metric_store.size }.to be >= 72

    if webserver_enabled
      # Wait http server is up
      wait(120).for {
        begin
          collector.snapshot_metric.metric_store.get_shallow(:http_address)
        rescue LogStash::Instrument::MetricStore::MetricNotFound => e
          nil
        end
      }.not_to be_nil
    end
  end

  after :each do
    agent.shutdown
    agent_task.wait
    LogStash::SETTINGS.set_value("api.enabled", @existing_api_enabled)
    LogStash::SETTINGS.set_value("monitoring.enabled", false)
  end

  context "new model" do
    context "with webserver disabled" do
      it_behaves_like("new model monitoring event with webserver setting") do
        let(:webserver_enabled) {false}
      end
    end

    context "with webserver enabled" do
      it_behaves_like("new model monitoring event with webserver setting") do
        let(:webserver_enabled) {true}
      end
    end
  end

 # TODO: fix issue https://github.com/elastic/logstash/issues/12711
 xcontext "old model" do
    it_behaves_like("old model monitoring event with webserver setting") do
      let(:webserver_enabled) {false}
    end
    it_behaves_like("old model monitoring event with webserver setting") do
      let(:webserver_enabled) {true}
    end
  end
end
