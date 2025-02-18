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

require_relative '../../framework/fixture'
require_relative '../../framework/settings'
require_relative '../../services/logstash_service'
require_relative '../../framework/helpers'
require "logstash/devutils/rspec/spec_helper"

describe "CLI > logstash-plugin remove" do
  before(:each) do
    @fixture = Fixture.new(__FILE__)
    @logstash_plugin = @fixture.get_service("logstash").plugin_cli
  end

    if RbConfig::CONFIG["host_os"] == "linux"
      context "without internet connection (linux seccomp wrapper)" do
        let(:offline_wrapper_path) { File.expand_path(File.join(File.dirname(__FILE__), "..", "..", "fixtures", "offline_wrapper")) }
        let(:offline_wrapper_cmd) { File.join(offline_wrapper_path, "offline") }

        before do
          Dir.chdir(offline_wrapper_path) do
            system("make clean")
            system("make")
          end
        end

        context "when no other plugins depends on this plugin" do
          let(:test_plugin) { "logstash-filter-qatest" }

          before :each do
            @logstash_plugin.install(File.join(File.dirname(__FILE__), "..", "..", "fixtures", "logstash-filter-qatest-0.1.1.gem"))
          end

          it "successfully remove the plugin" do
            execute = @logstash_plugin.run_raw("#{offline_wrapper_cmd} bin/logstash-plugin remove #{test_plugin}")

            expect(execute.exit_code).to eq(0)
            expect(execute.stderr_and_stdout).to match(/Successfully removed #{test_plugin}/)

            presence_check = @logstash_plugin.list(test_plugin)
            expect(presence_check.exit_code).to eq(1)
            expect(presence_check.stderr_and_stdout).to match(/ERROR: No plugins found/)
          end
        end

        context "when other plugins depends on this plugin" do
          it "refuses to remove the plugin and display the plugin that depends on it." do
            execute = @logstash_plugin.run_raw("#{offline_wrapper_cmd} bin/logstash-plugin remove logstash-codec-json")

            expect(execute.exit_code).to eq(1)
            expect(execute.stderr_and_stdout).to match(/Failed to remove "logstash-codec-json"/)
            expect(execute.stderr_and_stdout).to match(/logstash-integration-kafka/) # one of the dependency
            expect(execute.stderr_and_stdout).to match(/logstash-output-udp/) # one of the dependency

            presence_check = @logstash_plugin.list("logstash-codec-json")

            expect(presence_check.exit_code).to eq(0)
            expect(presence_check.stderr_and_stdout).to match(/logstash-codec-json/)
          end
        end
      end
    else
      context "when no other plugins depends on this plugin" do
        let(:test_plugin) { "logstash-filter-qatest" }

        before :each do
          @logstash_plugin.install(File.join(File.dirname(__FILE__), "..", "..", "fixtures", "logstash-filter-qatest-0.1.1.gem"))
        end

        it "successfully remove the plugin" do
          execute = @logstash_plugin.remove(test_plugin)

          expect(execute.exit_code).to eq(0)
          expect(execute.stderr_and_stdout).to match(/Successfully removed #{test_plugin}/)

          presence_check = @logstash_plugin.list(test_plugin)
          expect(presence_check.exit_code).to eq(1)
          expect(presence_check.stderr_and_stdout).to match(/ERROR: No plugins found/)
        end
      end

      context "when other plugins depends on this plugin" do
        it "refuses to remove the plugin and display the plugin that depends on it." do
          execute = @logstash_plugin.remove("logstash-codec-json")

          expect(execute.exit_code).to eq(1)
          expect(execute.stderr_and_stdout).to match(/Failed to remove "logstash-codec-json"/)
          expect(execute.stderr_and_stdout).to match(/logstash-integration-kafka/) # one of the dependency
          expect(execute.stderr_and_stdout).to match(/logstash-output-udp/) # one of the dependency

          presence_check = @logstash_plugin.list("logstash-codec-json")

          expect(presence_check.exit_code).to eq(0)
          expect(presence_check.stderr_and_stdout).to match(/logstash-codec-json/)
        end
      end

      context "multiple plugins" do

        let(:setup_plugin_list) do
          fail("spec must override `setup_plugin_list`")
        end

        before(:each) do
          if setup_plugin_list.any?
            search_dir = File.expand_path(File.join(__dir__, "..", "..", "fixtures", "plugins"))
            plugin_paths = []

            aggregate_failures('setup: resolve plugin paths') do
              setup_plugin_list.each do |requested_plugin|
                found = Dir.glob(File.join(search_dir, "#{requested_plugin}-*.gem"))
                expect(found).to have_attributes(:size => 1), lambda { "expected exactly one `#{requested_plugin}` in `#{search_dir}`, got #{found.inspect}" }
                plugin_paths << found.first
              end
            end

            aggregate_failures('setup: installing plugins') do
              puts "installing plugins #{plugin_paths.inspect}"
              outcome = @logstash_plugin.install(*plugin_paths)

              expect(outcome.exit_code).to eq(0)
              expect(outcome.stderr_and_stdout).to match(/Installation successful/)
            end
          end
        end

        context "when a remaining plugin has a dependency on a removed plugin" do
          let(:setup_plugin_list) do
            %w(
              logstash-filter-zero_no_dependencies
              logstash-filter-one_no_dependencies
              logstash-filter-two_depends_on_one
              logstash-filter-three_no_dependencies
              logstash-filter-four_depends_on_one_and_three
            )
          end
          it "errors helpfully without removing any of the plugins" do
            execute = @logstash_plugin.remove("logstash-filter-three_no_dependencies", "logstash-filter-zero_no_dependencies")

            expect(execute.exit_code).to eq(1)
            expect(execute.stderr_and_stdout).to include('Failed to remove "logstash-filter-three_no_dependencies"')
            expect(execute.stderr_and_stdout).to include("* logstash-filter-four_depends_on_one_and_three") # one of the dependency
            expect(execute.stderr_and_stdout).to include("No plugins were removed.")

            aggregate_failures("list plugins") do
              presence_check = @logstash_plugin.list
              expect(presence_check.exit_code).to eq(0)
              expect(presence_check.stderr_and_stdout).to include('logstash-filter-three_no_dependencies')
              expect(presence_check.stderr_and_stdout).to include('logstash-filter-zero_no_dependencies')
            end
          end
        end
        context "when multiple remaining plugins have a dependency on a removed plugin" do
          let(:setup_plugin_list) do
            %w(
              logstash-filter-zero_no_dependencies
              logstash-filter-one_no_dependencies
              logstash-filter-two_depends_on_one
              logstash-filter-three_no_dependencies
              logstash-filter-four_depends_on_one_and_three
            )
          end
          it "errors helpfully without removing any of the plugins" do
            execute = @logstash_plugin.remove("logstash-filter-one_no_dependencies", "logstash-filter-zero_no_dependencies")

            expect(execute.exit_code).to eq(1)
            expect(execute.stderr_and_stdout).to include('Failed to remove "logstash-filter-one_no_dependencies"')
            expect(execute.stderr_and_stdout).to include("* logstash-filter-four_depends_on_one_and_three") # one of the dependency
            expect(execute.stderr_and_stdout).to include("* logstash-filter-two_depends_on_one") # one of the dependency
            expect(execute.stderr_and_stdout).to include("No plugins were removed.")

            aggregate_failures("list plugins") do
              presence_check = @logstash_plugin.list
              expect(presence_check.exit_code).to eq(0)
              expect(presence_check.stderr_and_stdout).to include('logstash-filter-one_no_dependencies')
              expect(presence_check.stderr_and_stdout).to include('logstash-filter-zero_no_dependencies')
            end
          end
        end
        context "when removing plugins and all plugins that depend on them" do
          let(:setup_plugin_list) do
            %w(
              logstash-filter-zero_no_dependencies
              logstash-filter-one_no_dependencies
              logstash-filter-two_depends_on_one
              logstash-filter-three_no_dependencies
              logstash-filter-four_depends_on_one_and_three
            )
          end
          it "removes the plugins" do
            plugins_to_remove = %w(
              logstash-filter-one_no_dependencies
              logstash-filter-two_depends_on_one
              logstash-filter-three_no_dependencies
              logstash-filter-four_depends_on_one_and_three
            ).shuffle #random order
            execute = @logstash_plugin.remove(*plugins_to_remove)

            aggregate_failures("removal action") do
              expect(execute).to have_attributes(:exit_code => 0, :stderr_and_stdout => include("Success"))
              plugins_to_remove.each do |gem_name|
                expect(execute.stderr_and_stdout).to include("Successfully removed #{gem_name}")
              end
            end

            aggregate_failures("list plugins") do
              presence_check = @logstash_plugin.list
              expect(presence_check.exit_code).to eq(0)
              aggregate_failures("removed plugins") do
                plugins_to_remove.each do |expected_removed_plugin|
                  expect(presence_check.stderr_and_stdout).to_not include(expected_removed_plugin)
                end
              end
              aggregate_failures("non-removed plugins") do
                (setup_plugin_list - plugins_to_remove).each do |expected_remaining_plugin|
                  expect(presence_check.stderr_and_stdout).to include(expected_remaining_plugin)
                end
              end
            end
          end
        end
      end
    end
end
