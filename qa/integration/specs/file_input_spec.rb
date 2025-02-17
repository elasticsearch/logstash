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

require_relative '../framework/fixture'
require_relative '../framework/settings'
require "stud/temporary"
require "stud/try"
require "rspec/wait"
require "yaml"
require "fileutils"

describe "File Input" do
  before(:all) do
    @fixture = Fixture.new(__FILE__)
  end

  after :each do
    logstash_service.teardown
  end

  let(:temp_dir) { Stud::Temporary.directory("logstash-file-test") }
  let(:max_retry) { 120 }
  let(:logstash_service) { @fixture.get_service("logstash") }
  let(:log_path) do
    tmp_path = Stud::Temporary.file.path #get around ignore older completely
    source = File.expand_path(@fixture.input)
    FileUtils.cp(source, tmp_path)
    tmp_path
  end
  let(:timeout) { 90 } # seconds
  let(:number_of_events) do
    File.open(File.expand_path(@fixture.input), "r").readlines.size
  end


  shared_examples "send events" do

    it "successfully send events" do
      logstash_service.start_background(logstash_config)

      # It can take some delay for filebeat to connect to logstash and start sending data.
      # Its possible that logstash isn't completely initialized here, we can get "Connection Refused"
      begin
        sleep(1) while (logstash_service.monitoring_api.event_stats).nil?
      rescue
        retry
      end

      Stud.try(max_retry.times, RSpec::Expectations::ExpectationNotMetError) do
         result = logstash_service.monitoring_api.event_stats
         expect(result["in"]).to eq(number_of_events)
      end
    end

    it 'should not crash the plugin' do
      spawn_logstash_and_wait_for_exit! logstash_config, timeout
      log_file = "#{temp_dir}/logstash-plain.log"
      expect( File.exists?(log_file) ).to be true
      expect( File.read(log_file) ).not_to match /A plugin had an unrecoverable error/
    end
  end

  context "Read mode" do
    let(:logstash_config) { @fixture.config("read_mode", { :log_path => log_path }) }

    include_examples "send events"
  end

  def spawn_logstash_and_wait_for_exit!(config, timeout)
    logstash_service.spawn_logstash('-w', '1', '--path.logs', temp_dir, '-e', config)

    time = Time.now
    while (Time.now - time) < timeout
      sleep(0.1)
      break if logstash_service.exited?
    end
  end
end
