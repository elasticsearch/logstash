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
require "bundler/cli"

describe LogStash::Bundler do
  context "capture_stdout" do
    it "should capture stdout from block" do
      original_stdout = $stdout
      output, exception = LogStash::Bundler.capture_stdout do
        expect($stdout).not_to eq(original_stdout)
        puts("foobar")
      end
      expect($stdout).to eq(original_stdout)
      expect(output).to eq("foobar\n")
      expect(exception).to eq(nil)
    end

    it "should capture stdout and report exception from block" do
      output, exception = LogStash::Bundler.capture_stdout do
        puts("foobar")
        raise(StandardError, "baz")
      end
      expect(output).to eq("foobar\n")
      expect(exception).to be_a(StandardError)
      expect(exception.message).to eq("baz")
    end
  end

  context 'when invoking bundler' do
    original_stderr = $stderr

    subject { LogStash::Bundler.invoke!(options) }

    # by default we want to fail fast on the test
    let(:options) { { :install => true, :max_tries => 0, :without => [:development]} }
    let(:bundler_args) { LogStash::Bundler.bundler_arguments(options) }

    before do
      $stderr = StringIO.new

      expect(::Bundler).to receive(:reset!).at_least(1)
    end

    after do
      expect(::Bundler.settings[:path]).to eq(LogStash::Environment::BUNDLE_DIR)
      expect(::Bundler.settings[:gemfile]).to eq(LogStash::Environment::GEMFILE_PATH)
      expect(::Bundler.settings[:without]).to eq(options.fetch(:without, []))

      expect(ENV['GEM_PATH']).to eq(LogStash::Environment.logstash_gem_home)

      $stderr = original_stderr
    end

    it 'should call Bundler::CLI.start with the correct arguments' do
      allow(ENV).to receive(:replace)
      expect(::Bundler::CLI).to receive(:start).with(bundler_args)
      expect(ENV).to receive(:replace) do |args|
        expect(args).to include("BUNDLE_PATH" => LogStash::Environment::BUNDLE_DIR,
                                                            "BUNDLE_GEMFILE" => LogStash::Environment::GEMFILE_PATH,
                                                            "BUNDLE_SILENCE_ROOT_WARNING" => "true",
                                                            "BUNDLE_WITHOUT" => "development")
      end
      expect(ENV).to receive(:replace) do |args|
        expect(args).not_to include(
                                "BUNDLE_PATH" => LogStash::Environment::BUNDLE_DIR,
                                "BUNDLE_SILENCE_ROOT_WARNING" => "true",
                                "BUNDLE_WITHOUT" => "development")
      end

      LogStash::Bundler.invoke!(options)
    end

    context 'abort with an exception' do
      it 'gem conflict' do
        allow(::Bundler::CLI).to receive(:start).with(bundler_args) { raise ::Bundler::SolveFailure.new('conflict') }
        expect { subject }.to raise_error(::Bundler::SolveFailure)
      end

      it 'gem is not found' do
        allow(::Bundler::CLI).to receive(:start).with(bundler_args) { raise ::Bundler::GemNotFound.new('conflict') }
        expect { subject }.to raise_error(::Bundler::GemNotFound)
      end

      it 'on max retries' do
        options.merge!({ :max_tries => 2 })
        expect(::Bundler::CLI).to receive(:start).with(bundler_args).at_most(options[:max_tries] + 1) { raise RuntimeError }
        expect { subject }.to raise_error(RuntimeError)
      end
    end
  end

  context 'when generating bundler arguments' do
    subject(:bundler_arguments) { LogStash::Bundler.bundler_arguments(options) }
    let(:options) { {} }

    context 'when installing' do
      let(:options) { { :install => true } }

      it 'should call bundler install' do
        expect(bundler_arguments).to include('install')
      end

      context 'with the cleaning option' do
        it 'should add the --clean arguments' do
          options.merge!(:clean => true)
          expect(bundler_arguments).to include('install', '--clean')
        end
      end
    end

    context "when updating" do
      let(:options) { { :update => 'logstash-input-stdin' } }

      context 'with a specific plugin' do
        it 'should call `bundle update plugin-name`' do
          expect(bundler_arguments).to include('update', 'logstash-input-stdin')
        end
      end

      context 'with the cleaning option' do
        it 'should ignore the clean option' do
          options.merge!(:clean => true)
          expect(bundler_arguments).not_to include('--clean')
        end
      end

      context "level: major" do
        let(:options) { super().merge(:level => "major") }
        it "invokes bundler with --minor" do
          expect(bundler_arguments).to include("--major")
        end
      end

      context "level: minor" do
        let(:options) { super().merge(:level => "minor") }
        it "invokes bundler with --minor" do
          expect(bundler_arguments).to include("--minor")
        end
      end

      context "level: patch" do
        let(:options) { super().merge(:level => "patch") }
        it "invokes bundler with --minor" do
          expect(bundler_arguments).to include("--patch")
        end
      end

      context "level: unspecified" do
        it "invokes bundler with --minor" do
          expect(bundler_arguments).to include("--minor")
        end
      end

      context 'with ecs_compatibility' do
        let(:plugin_name) { 'logstash-output-elasticsearch' }
        let(:options) { { :update => plugin_name } }

        it "also update dependencies" do
          expect(bundler_arguments).to include('logstash-mixin-ecs_compatibility_support', plugin_name)

          mixin_libs = bundler_arguments - ["update", "--minor", plugin_name]
          mixin_libs.each do |gem_name|
            dep = ::Gem::Dependency.new(gem_name)
            expect(dep.type).to eq(:runtime)
            expect(gem_name).to start_with('logstash-mixin-')
          end
        end

        it "do not include core lib" do
          expect(bundler_arguments).not_to include('logstash-core', 'logstash-core-plugin-api')
        end

        it "raise error when fetcher failed" do
          allow(::Gem::SpecFetcher.fetcher).to receive("spec_for_dependency").with(anything).and_return([nil, [StandardError.new("boom")]])
          expect { bundler_arguments }.to raise_error(StandardError, /boom/)
        end
      end
    end

    context "when only specifying clean" do
      let(:options) { { :clean => true } }
      it 'should call the `bundle clean`' do
        expect(bundler_arguments).to include('clean')
      end
    end
  end
end
