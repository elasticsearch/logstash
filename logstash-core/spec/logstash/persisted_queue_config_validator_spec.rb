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
require "tmpdir"
require "logstash/persisted_queue_config_validator"
require 'securerandom'
require_relative '../support/helpers'

describe LogStash::PersistedQueueConfigValidator do
  context("when persisted queues are enabled") do
    let(:input_block) { "input { generator {} }" }
    let(:config_path) { temporary_file(input_block) }
    let(:queue_path) { Stud::Temporary.directory }
    let(:settings) do
      mock_settings(
        "queue.type" => "persisted",
        "queue.page_capacity" => 1024,
        "path.queue" => queue_path,
        "path.config" => config_path
      )
    end
    let(:pipeline_configs) { LogStash::Config::Source::Local.new(settings).pipeline_configs }
    let(:pq_config_validator) { LogStash::PersistedQueueConfigValidator.new }

    context("'queue.max_bytes' is less than 'queue.page_capacity'") do
      it "should throw" do
        settings.set_value("queue.max_bytes", 512)
        expect { pq_config_validator.check({}, pipeline_configs) }
          .to raise_error(LogStash::BootstrapCheckError, /'queue.page_capacity' must be less than or equal to 'queue.max_bytes'/)
      end
    end

    context("'queue.max_bytes' = 0 which is less than 'queue.page_capacity'") do
      it "should not throw" do
        expect(pq_config_validator.logger).not_to receive(:warn)
        settings.set_value("queue.max_bytes", 0)
        pq_config_validator.check({}, pipeline_configs)
      end
    end

    context("queue size is greater than 'queue.max_bytes'") do
      let(:pipeline_id) { "main" }
      let(:page_file) do
        FileUtils.mkdir_p(::File.join(queue_path, pipeline_id))
        ::File.new(::File.join(queue_path, pipeline_id, "page.0"), "w")
      end

      before do
        # create a 2MB file
        ::File.open(page_file, 'wb') do |f|
          f.write(SecureRandom.random_bytes(2**21))
        end
      end

      it "should throw" do
        expect(pq_config_validator.logger).to receive(:warn).once.with(/greater than 'queue.max_bytes'/)
        settings.set_value("queue.max_bytes", "1mb")
        pq_config_validator.check({}, pipeline_configs)
      end

      after do
        page_file.truncate(0)
        page_file.close
      end
    end

    context("disk does not have sufficient space") do
      let(:pipeline_id) { "main" }
      # Create a pipeline config double that matches what the class expects
      let(:pipeline_config) do
        double("PipelineConfig").tap do |config|
          allow(config).to receive(:pipeline_id).and_return(pipeline_id)
          allow(config).to receive(:settings).and_return(
            double("Settings").tap do |s|
              allow(s).to receive(:get).with("queue.type").and_return("persisted")
              allow(s).to receive(:get).with("queue.max_bytes").and_return(300 * 1024 * 1024 * 1024) # 300GB
              allow(s).to receive(:get).with("queue.page_capacity").and_return(64 * 1024 * 1024) # 64MB
              allow(s).to receive(:get).with("pipeline.id").and_return(pipeline_id)
              allow(s).to receive(:get).with("path.queue").and_return(queue_path)
            end
          )
        end
      end

      before do
        allow(Dir).to receive(:glob).and_return(["page.1"])
        allow(File).to receive(:size).and_return(25 * 1024 * 1024 * 1024)
        allow(FsUtil).to receive(:hasFreeSpace).and_return(false)
        allow(Files).to receive(:exists).and_return(true)

        # Mock filesystem
        mock_file_store = double("FileStore",
          name: "disk1",
          getUsableSpace: 100 * 1024 * 1024 * 1024  # 100GB free
        )
        allow(Files).to receive(:getFileStore).and_return(mock_file_store)
      end

      it "reports detailed space information" do
        expect(pq_config_validator).to receive(:check_disk_space) do |_, _, required_free_bytes|
          expect(required_free_bytes.size).to eq(1)
          expect(required_free_bytes.values[0]).to eq(300 * 1024 * 1024 * 1024)
        end.and_call_original

        expect(pq_config_validator.logger).to receive(:warn).once do |msg|
          expect(msg).to include("Total space required: 300gb")
          expect(msg).to include("Current PQ usage: 25gb")
        end

        pq_config_validator.check({}, [pipeline_config])
      end

      context "with multiple pipelines" do
        let(:pipeline_id1) { "main" }
        let(:pipeline_id2) { "secondary" }
        let(:pipeline_id3) { "third" }

        let(:base_queue_path) { queue_path }
        let(:queue_path1) { ::File.join(base_queue_path, pipeline_id1) }
        let(:queue_path2) { ::File.join(base_queue_path, pipeline_id2) }
        let(:queue_path3) { ::File.join(Stud::Temporary.directory, pipeline_id3) }

        let(:pipeline_config1) do
          double("PipelineConfig").tap do |config|
            allow(config).to receive(:pipeline_id).and_return(pipeline_id1)
            allow(config).to receive(:settings).and_return(
              double("Settings").tap do |s|
                allow(s).to receive(:get).with("queue.type").and_return("persisted")
                allow(s).to receive(:get).with("queue.max_bytes").and_return(300 * 1024 * 1024 * 1024)
                allow(s).to receive(:get).with("queue.page_capacity").and_return(64 * 1024 * 1024)
                allow(s).to receive(:get).with("pipeline.id").and_return(pipeline_id1)
                allow(s).to receive(:get).with("path.queue").and_return(base_queue_path)
              end
            )
          end
        end

        let(:pipeline_config2) do
          double("PipelineConfig").tap do |config|
            allow(config).to receive(:pipeline_id).and_return(pipeline_id2)
            allow(config).to receive(:settings).and_return(
              double("Settings").tap do |s|
                allow(s).to receive(:get).with("queue.type").and_return("persisted")
                allow(s).to receive(:get).with("queue.max_bytes").and_return(300 * 1024 * 1024 * 1024)
                allow(s).to receive(:get).with("queue.page_capacity").and_return(64 * 1024 * 1024)
                allow(s).to receive(:get).with("pipeline.id").and_return(pipeline_id2)
                allow(s).to receive(:get).with("path.queue").and_return(base_queue_path)
              end
            )
          end
        end

        let(:pipeline_config3) do
          double("PipelineConfig").tap do |config|
            allow(config).to receive(:pipeline_id).and_return(pipeline_id3)
            allow(config).to receive(:settings).and_return(
              double("Settings").tap do |s|
                allow(s).to receive(:get).with("queue.type").and_return("persisted")
                allow(s).to receive(:get).with("queue.max_bytes").and_return(300 * 1024 * 1024 * 1024)
                allow(s).to receive(:get).with("queue.page_capacity").and_return(64 * 1024 * 1024)
                allow(s).to receive(:get).with("pipeline.id").and_return(pipeline_id3)
                allow(s).to receive(:get).with("path.queue").and_return(::File.dirname(queue_path3))
              end
            )
          end
        end

        let(:mock_file_store1) { double("FileStore", name: "disk1", getUsableSpace: 100 * 1024 * 1024 * 1024) }
        let(:mock_file_store2) { double("FileStore", name: "disk2", getUsableSpace: 50 * 1024 * 1024 * 1024) }

        before do
          # Precise path matching for Dir.glob
          allow(Dir).to receive(:glob) do |pattern|
            case pattern
            when /#{pipeline_id1}.*page\.*/ then ["#{::File.dirname(pattern)}/page.1"]
            when /#{pipeline_id2}.*page\.*/ then ["#{::File.dirname(pattern)}/page.1", "#{::File.dirname(pattern)}/page.2"]
            when /#{pipeline_id3}.*page\.*/ then ["#{::File.dirname(pattern)}/page.1"]
            else []
            end
          end

          # Set up file size matching with full paths
          allow(File).to receive(:size) do |path|
            case
            when path.include?(pipeline_id1) then 30 * 1024 * 1024 * 1024 # 30GB for main
            when path.include?(pipeline_id2) then 25 * 1024 * 1024 * 1024 # 25GB for secondary
            when path.include?(pipeline_id3) then 25 * 1024 * 1024 * 1024 # 25GB for third
            else 0
            end
          end

          allow(Files).to receive(:getFileStore) do |path|
            case path.toString
            when /#{pipeline_id3}/ then mock_file_store2
            else mock_file_store1
            end
          end

          allow(FsUtil).to receive(:hasFreeSpace).and_return(false)
          allow(Files).to receive(:exists).and_return(true)
        end

        context "with multiple queues on same filesystem" do
          it "reports consolidated information for same filesystem" do
            expect(pq_config_validator.logger).to receive(:warn).once do |msg|
              expect(msg).to match(/Persistent queues require more disk space than is available on a filesystem:/)
              expect(msg).to match(/Filesystem 'disk1':/)
              expect(msg).to match(/Total space required: 600gb/) # 300GB * 2
              expect(msg).to match(/Current PQ usage: 80gb/) # 30GB + (2 * 25GB)
              expect(msg).to match(/Current size: 30gb/) # First queue
              expect(msg).to match(/Current size: 50gb/) # Second queue (2 files * 25GB)
            end

            pq_config_validator.check({}, [pipeline_config1, pipeline_config2])
          end
        end

        context "with queues across multiple filesystems" do
          it "reports separate information for each filesystem" do
            expect(pq_config_validator.logger).to receive(:warn).once do |msg|
              # First filesystem
              expect(msg).to match(/Filesystem 'disk1':/)
              expect(msg).to match(/Total space required: 600gb/) # 300GB * 2
              expect(msg).to match(/Current PQ usage: 80gb/) # 30GB + (2 * 25GB)

              # Second filesystem
              expect(msg).to match(/Filesystem 'disk2':/)
              expect(msg).to match(/Total space required: 300gb/) # 300GB
              expect(msg).to match(/Current PQ usage: 25gb/) # 25GB
            end

            pq_config_validator.check({}, [pipeline_config1, pipeline_config2, pipeline_config3])
          end
        end
      end
    end

    context("pipeline registry check queue config") do
      shared_examples "no update" do
        it "gives false" do
          expect(pq_config_validator.queue_configs_update?(running_pipelines, pipeline_configs))
            .to be_falsey
        end
      end

      shared_examples "got update" do
        it "gives true" do
          expect(pq_config_validator.queue_configs_update?(running_pipelines, pipeline_configs))
            .to be_truthy
        end
      end

      let(:java_pipeline) { LogStash::JavaPipeline.new(pipeline_configs[0]) }
      let(:running_pipelines) { {:main => java_pipeline } }

      context("pipeline config is identical") do
        it_behaves_like "no update"
      end

      context("add more pipeline") do
        let(:settings1) { settings.dup.merge("pipeline.id" => "main") }
        let(:settings2) { settings.dup.merge("pipeline.id" => "second") }
        let(:pipeline_configs) do
          LogStash::Config::Source::Local.new(settings1).pipeline_configs +
            LogStash::Config::Source::Local.new(settings2).pipeline_configs
        end

        it_behaves_like "got update"
      end

      context("queue configs has changed") do
        let(:settings1) { settings.dup.merge("queue.max_bytes" => "1mb") }
        let(:pipeline_configs1) { LogStash::Config::Source::Local.new(settings1).pipeline_configs }
        let(:java_pipeline) { LogStash::JavaPipeline.new(pipeline_configs1[0]) }

        it_behaves_like "got update"
      end

      context("queue configs do not changed") do
        let(:settings1) { settings.dup.merge("config.debug" => "true") }
        let(:pipeline_configs) { LogStash::Config::Source::Local.new(settings1).pipeline_configs }

        it_behaves_like "no update"
      end
    end

    context("cache check") do
      context("has update since last check") do
        let(:settings1) { settings.dup.merge("pipeline.id" => "main") }
        let(:settings2) { settings.dup.merge("pipeline.id" => "second") }
        let(:pipeline_configs2) do
          LogStash::Config::Source::Local.new(settings1).pipeline_configs +
            LogStash::Config::Source::Local.new(settings2).pipeline_configs
        end
        let(:pipeline_configs) do
          LogStash::Config::Source::Local.new(settings1).pipeline_configs
        end

        it "gives true when add a new pipeline " do
          pq_config_validator.instance_variable_set(:@last_check_pass, true)
          pq_config_validator.instance_variable_set(:@last_check_pipeline_configs, pipeline_configs)
          expect(pq_config_validator.cache_check_fail?(pipeline_configs2)).to be_truthy
        end

        it "gives false when remove a old pipeline" do
          pq_config_validator.instance_variable_set(:@last_check_pass, true)
          pq_config_validator.instance_variable_set(:@last_check_pipeline_configs, pipeline_configs2)
          expect(pq_config_validator.cache_check_fail?(pipeline_configs)).to be_falsey
        end
      end

      context("last check fail") do
        it "gives true" do
          pq_config_validator.instance_variable_set(:@last_check_pass, false)
          pq_config_validator.instance_variable_set(:@last_check_pipeline_configs, pipeline_configs)
          expect(pq_config_validator.cache_check_fail?(pipeline_configs)).to be_truthy
        end
      end

      context("no update and last check pass") do
        it "gives false" do
          pq_config_validator.instance_variable_set(:@last_check_pass, true)
          pq_config_validator.instance_variable_set(:@last_check_pipeline_configs, pipeline_configs)
          expect(pq_config_validator.cache_check_fail?(pipeline_configs)).to be_falsey
        end
      end
    end

    context("check") do
      context("add more pipeline and cache check pass") do
        it "does not check PQ size" do
          pq_config_validator.instance_variable_set(:@last_check_pass, true)
          pq_config_validator.instance_variable_set(:@last_check_pipeline_configs, pipeline_configs)
          expect(pq_config_validator).not_to receive(:check_disk_space)
          pq_config_validator.check({}, pipeline_configs)
        end
      end

      context("add more pipeline and cache is different") do
        it "check PQ size" do
          pq_config_validator.instance_variable_set(:@last_check_pass, true)
          pq_config_validator.instance_variable_set(:@last_check_pipeline_configs, [])
          expect(pq_config_validator).to receive(:check_disk_space).and_call_original
          pq_config_validator.check({}, pipeline_configs)
        end
      end
    end
  end
end
