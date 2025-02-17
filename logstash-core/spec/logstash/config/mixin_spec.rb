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
require "logstash/config/mixin"

describe LogStash::Config::Mixin do
  context "when encountering a deprecated option" do
    let(:password) { "sekret" }
    let(:deprecation_logger) { double("DeprecationLogger").as_null_object }
    let(:plugin_class) do
      Class.new(LogStash::Filters::Base) do
        include LogStash::Config::Mixin
        config_name "test_deprecated"
        milestone 1
        config :old_opt, :validate => :string, :deprecated => "this is old school"
        config :password, :validate => :password
      end
    end

    it "should not log the password" do
      instance = plugin_class.new("old_opt" => "whut", "password" => password)
      allow(instance).to receive(:deprecation_logger).and_return(deprecation_logger)

      expect(deprecation_logger).to receive(:deprecated) do |message, _|
        expect(message).to include("old_opt")
        expect(message).to include("this is old school")
        expect(message).not_to include(password)
      end

      instance.send(:config_init, instance.params)
    end
  end

  context 'DSL::validate_value(String, :codec)' do
    subject(:plugin_class) { Class.new(LogStash::Filters::Base) { config_name "test_deprecated_two" } }
    let(:codec_class) { Class.new(LogStash::Codecs::Base) { config_name 'dummy' } }
    let(:deprecation_logger) { double("DeprecationLogger").as_null_object }

    before(:each) do
      allow(plugin_class).to receive(:deprecation_logger).and_return(deprecation_logger)
      allow(LogStash::Plugin).to receive(:lookup).with("codec", codec_class.config_name).and_return(codec_class)
    end

    it 'instantiates the codec' do
      success, codec = plugin_class.validate_value(codec_class.config_name, :codec)

      expect(success).to be true
      expect(codec.class).to eq(codec_class)
    end

    it 'logs a deprecation' do
      plugin_class.validate_value(codec_class.config_name, :codec)
      expect(deprecation_logger).to have_received(:deprecated) do |message|
        expect(message).to include("validate_value(String, :codec)")
      end
    end
  end

  context "validating :field_reference" do
    let(:plugin_class) do
      Class.new(LogStash::Filters::Base) do
        config :target, :validate => :field_reference
      end
    end
    let(:params) do
      { "target" => target_param }
    end

    before(:each) do
      allow(plugin_class).to receive(:logger).and_return(double('Logger').as_null_object)
    end

    context "when input is valid" do
      let(:target_param) { "[@metadata][target]" }
      it 'successfully initializes the plugin' do
        expect(plugin_class.new(params)).to be_a_kind_of plugin_class
      end
      it 'coerces the value' do
        instance = plugin_class.new(params)
        expect(instance.target).to_not be_nil
        expect(instance.target).to eq(target_param)
      end
    end

    context "when input is invalid" do
      let(:target_param) { "][Nv@l][d" }
      it 'does not initialize the plugin' do
        expect { plugin_class.new(params) }.to raise_exception(LogStash::ConfigurationError)
        expect(plugin_class.logger).to have_received(:error).with(/must be a field_reference/)
      end
    end
  end

  context "when validating :bytes successfully" do
    subject do
      local_num_bytes = num_bytes # needs to be locally scoped :(
      Class.new(LogStash::Filters::Base) do
        include LogStash::Config::Mixin
        config_name "test"
        milestone 1
        config :size_bytes, :validate => :bytes
        config :size_default, :validate => :bytes, :default => "#{local_num_bytes}"
        config :size_upcase, :validate => :bytes
        config :size_downcase, :validate => :bytes
        config :size_space, :validate => :bytes
      end.new({
        "size_bytes" => "#{local_num_bytes}",
        "size_upcase" => "#{local_num_bytes}KiB".upcase,
        "size_downcase" => "#{local_num_bytes}KiB".downcase,
        "size_space" => "#{local_num_bytes} KiB"
      })
    end

    let!(:num_bytes) { rand(1000) }
    let!(:num_kbytes) { num_bytes * 1024 }

    it "should validate :bytes successfully with no units" do
      expect(subject.size_bytes).to eq(num_bytes)
    end

    it "should allow setting valid default" do
      expect(subject.size_default).to eq(num_bytes)
    end

    it "should be case-insensitive when parsing units" do
      expect(subject.size_upcase).to eq(num_kbytes)
      expect(subject.size_downcase).to eq(num_kbytes)
    end

    it "should accept one space between num_bytes and unit suffix" do
      expect(subject.size_space).to eq(num_kbytes)
    end
  end

  context "when raising configuration errors while validating" do
    it "should raise configuration error when provided with invalid units" do
      expect {
        Class.new(LogStash::Filters::Base) do
          include LogStash::Config::Mixin
          config_name "test"
          milestone 1
          config :size_file, :validate => :bytes
        end.new({"size_file" => "10 yolobytes"})
      }.to raise_error(LogStash::ConfigurationError)
    end

    it "should raise configuration error when provided with too many spaces" do
      expect {
        Class.new(LogStash::Filters::Base) do
          include LogStash::Config::Mixin
          config_name "test"
          milestone 1
          config :size_file, :validate => :bytes
        end.new({"size_file" => "10  kib"})
      }.to raise_error(LogStash::ConfigurationError)
    end
  end

  context "when validating lists of items" do
    let(:klass) do
      Class.new(LogStash::Filters::Base)  do
        config_name "list_validator_spec"
        config :strings, :validate => :string, :list => true
        config :required_strings, :validate => :string, :list => true, :required => true
      end
    end

    let(:strings) { ["I am a", "modern major general"] }
    let(:required_strings) { ["required", "strings"] }

    let(:config) do
      {"strings" => strings, "required_strings" => required_strings}
    end

    subject(:instance) { klass.new(config) }

    it "a string list should return an array of strings" do
      expect(subject.strings).to match_array(strings)
    end

    context 'URI lists' do
      let(:klass) do
        Class.new(LogStash::Filters::Base) do
          config_name 'list_uri_validator_spec'
          config :uris, :validate => :uri, :list => true
        end
      end
      subject(:instance) { klass.new(config) }

      let(:uri_1) { "http://example.net/1" }
      let(:uri_2) { "http://example.net/2" }
      let(:uri_3) { "http://example.net:9201/3" }

      let(:uris) { [uri_1, uri_2, uri_3] }
      let(:config) { Hash["uris" => uris_parameter] }

      let(:safe_uris) { uris.map {|str| ::LogStash::Util::SafeURI.new(str) } }

      shared_examples ':validate => :uri_list' do
        it 'should normalize to a flat list containing all extracted URIs from the input' do
          expect(instance.uris).to match_array(safe_uris)
        end
      end

      context 'when given a single string containing exactly one uri' do
        let(:uris_parameter) { "#{uri_1}" }
        let(:uris) { [uri_1] }
        include_examples ':validate => :uri_list'
      end

      context 'when given an array of strings, each containing exactly one uri' do
        let(:uris_parameter) { uris }
        include_examples ':validate => :uri_list'
      end

      context 'when given a single string containing multiple whitespace-delimited uris' do
        let(:uris_parameter) { "#{uri_1} #{uri_2} #{uri_3}" }
        include_examples ':validate => :uri_list'
      end

      context 'when given an array containing a single entry that has multiple whitespace-delimited uris' do
        let(:uris_parameter) { ["#{uri_1} #{uri_2} #{uri_3}"] }
        include_examples ':validate => :uri_list'
      end

      context 'when given an array containing multiple entries, one of which has multiple whitespace-delimited uris' do
        let(:uris_parameter) { ["#{uri_1} #{uri_2}", "#{uri_3}"] }
        include_examples ':validate => :uri_list'
      end
    end

    context "with a scalar value" do
      let(:strings) { "foo" }

      it "should return the scalar value as a single element array" do
        expect(subject.strings).to match_array([strings])
      end
    end

    context "with an empty list" do
      let(:strings) { [] }

      it "should return an empty list" do
        expect(subject.strings).to be_empty
      end
    end

    describe "with required => true" do
      context "and a single element" do
        let(:required_strings) { ["foo"] }

        it "should return the single value" do
          expect(subject.required_strings).to eql(required_strings)
        end
      end

      context "with an empty list" do
        let (:required_strings) { [] }

        it "should raise a configuration error" do
          expect { subject.required_strings }.to raise_error(LogStash::ConfigurationError)
        end
      end

      context "with no value specified" do
        let (:required_strings) { nil }

        it "should raise a configuration error" do
          expect { subject.required_strings }.to raise_error(LogStash::ConfigurationError)
        end
      end
    end
  end

  context "when validating :string" do
    let(:plugin_class) do
      Class.new(LogStash::Filters::Base) do
        config "string_option", :validate => :string
      end
    end
    let(:params) { {'string_option' => parameter_value} }

    before(:each) do
      allow(plugin_class).to receive(:logger).and_return(double('Logger').as_null_object)
    end

    context 'and input is a string' do
      let(:parameter_value) { 'a string' }
      it 'successfully initializes the plugin' do
        expect(plugin_class.new(params)).to be_a_kind_of plugin_class
      end
      it 'holds the value' do
        instance = plugin_class.new(params)
        expect(instance.string_option).to_not be_nil
        expect(instance.string_option).to eq(parameter_value)
      end
    end

    context 'and input is multiple items' do
      let(:parameter_value) { ['one string', 'another string'] }
      it 'does not initialize the plugin' do
        expect { plugin_class.new(params) }.to raise_exception(LogStash::ConfigurationError)
        expect(plugin_class.logger).to have_received(:error).with(/Expected string/)
      end
    end

    # Config AST favors Numeric to Bareword and handles unquoted number-like nodes as having a numeric value.
    # We need to ensure that the config DSL maps these to their stringified counterpart
    context 'and input is a number' do
      let(:parameter_value) { 12345 }
      it 'successfully initializes the plugin' do
        expect(plugin_class.new(params)).to be_a_kind_of plugin_class
      end
      it 'holds a stringified value' do
        instance = plugin_class.new(params)
        expect(instance.string_option).to_not be_nil
        expect(instance.string_option).to eq('12345')
      end
    end
  end

  context "when validating :password" do
    shared_examples 'protected password' do
      let(:secret) { 'fancy pants' }
      let(:plugin_class) do
        Class.new(LogStash::Filters::Base)  do
          config_name "fake"
          config :password, :validate => :password
        end
      end
      subject(:plugin_instance) { plugin_class.new(instance_params) }

      it "should be a Password object" do
        expect(plugin_instance.password).to(be_a(LogStash::Util::Password))
      end

      it "should make password values hidden" do
        expect(plugin_instance.password.to_s).to(be == "<password>")
        expect(plugin_instance.password.inspect).to(be == "<password>")
      end

      it "should show password values via #value" do
        expect(plugin_instance.password.value).to(be == secret)
      end

      it "should correctly copy password types" do
        clone = plugin_instance.class.new(plugin_instance.params)
        expect(clone.password.value).to(be == secret)
      end

      it "should obfuscate original_params" do
        expect(plugin_instance.original_params['password']).to(be_a(LogStash::Util::Password))
      end
    end

    context 'when instantiated with a string literal password' do
      it_behaves_like 'protected password' do
        let(:instance_params) { { "password" => secret } }
      end
    end

    # Config AST handles number-like nodes as having a numeric value,
    # and instantiates plugins without first converting them. We need to
    # ensure that the config DSL maps these to their stringified counterpart
    context 'when instantiated with a number literal password' do
      it_behaves_like 'protected password' do
        let(:secret) { '12345' }
        let(:instance_params) { { 'password' => 12345 } }
      end
    end

    context 'when instantiated with an environment variable placeholder' do
      it_behaves_like 'protected password' do
        let(:instance_params) { { "password" => '${PLACEHOLDER}'} }
        before(:each) { ENV.store('PLACEHOLDER', secret) }
        after(:each) { ENV.delete('PLACEHOLDER')}

        before(:each) do
          # Ensure the shared examples are actually running with an
          # environment variable placeholder.
          # If this assertion fails, setup for the spec is invalid.
          expect(instance_params['password']).to eq('${PLACEHOLDER}')
        end
      end
    end
  end

  context "when validating :uri" do
    let(:klass) do
      Class.new(LogStash::Filters::Base)  do
        config_name "fakeuri"
        config :uri, :validate => :uri
      end
    end

    shared_examples("safe URI") do |options|
      options ||= {}

      subject { klass.new("uri" => uri_str) }

      it "should be a SafeURI object" do
        expect(subject.uri).to(be_a(LogStash::Util::SafeURI))
      end

      it "should correctly copy URI types" do
        clone = subject.class.new(subject.params)
        expect(clone.uri.to_s).to eql(uri_hidden)
      end

      it "should make the real java.net.URI object available under #uri" do
        expect(subject.uri.uri).to be_a(java.net.URI)
      end

      it "should obfuscate original_params" do
        expect(subject.original_params['uri']).to(be_a(LogStash::Util::SafeURI))
      end

      if !options[:exclude_password_specs]
        describe "passwords" do
          it "should make password values hidden with #to_s" do
            expect(subject.uri.to_s).to eql(uri_hidden)
          end

          it "should make password values hidden with #inspect" do
            expect(subject.uri.inspect).to eql(uri_hidden)
          end
        end
      end

      context "attributes" do
        [:scheme, :user, :password, :hostname, :path].each do |attr|
          it "should make #{attr} available" do
            expect(subject.uri.send(attr)).to eql(self.send(attr))
          end
        end
      end
    end

    context "with a host:port combination" do
      let(:scheme) { nil }
      let(:user) { nil }
      let(:password) { nil }
      let(:hostname) { "myhostname" }
      let(:port) { 1234 }
      let(:path) { "" }
      let(:uri_str) { "#{hostname}:#{port}" }
      let(:uri_hidden) { "//#{hostname}:#{port}" }

      include_examples("safe URI", :exclude_password_specs => true)
    end

    context "with a username / password" do
      let(:scheme) { "myscheme" }
      let(:user) { "myuser" }
      let(:password) { "fancypants" }
      let(:hostname) { "myhostname" }
      let(:path) { "/my/path" }
      let(:uri_str) { "#{scheme}://#{user}:#{password}@#{hostname}#{path}" }
      let(:uri_hidden) { "#{scheme}://#{user}:#{LogStash::Util::SafeURI::PASS_PLACEHOLDER}@#{hostname}#{path}" }

      include_examples("safe URI")
    end

    context "without a username / password" do
      let(:scheme) { "myscheme" }
      let(:user) { nil }
      let(:password) { nil }
      let(:hostname) { "myhostname" }
      let(:path) { "/my/path" }
      let(:uri_str) { "#{scheme}://#{hostname}#{path}" }
      let(:uri_hidden) { "#{scheme}://#{hostname}#{path}" }

      include_examples("safe URI")
    end
  end

  describe "obsolete settings" do
    let(:plugin_class) do
      Class.new(LogStash::Inputs::Base) do
        include LogStash::Config::Mixin
        config_name "example"
        config :foo, :validate => :string, :obsolete => "This feature was removed."
      end
    end

    context "when using an obsolete setting" do
      it "should cause a configuration error" do
        expect {
          plugin_class.new("foo" => "hello")
        }.to raise_error(LogStash::ConfigurationError)
      end
    end

    context "when using an obsolete settings from the parent class" do
      it "should cause a configuration error" do
        expect {
          plugin_class.new("debug" => true)
        }.to raise_error(LogStash::ConfigurationError)
      end
    end

    context "when not using an obsolete setting" do
      it "should not cause a configuration error" do
        expect {
          plugin_class.new({})
        }.not_to raise_error
      end
    end
  end

  context "#params" do
    let(:plugin_class) do
      Class.new(LogStash::Filters::Base)  do
        config_name "fake"
        config :password, :validate => :password
        config :bad, :validate => :string, :default => "my default", :obsolete => "not here"
      end
    end

    subject { plugin_class.new({ "password" => "secret" }) }

    it "should not return the obsolete options" do
      expect(subject.params).not_to include("bad")
    end

    it "should include any other params" do
      expect(subject.params).to include("password")
    end
  end

  context "environment variable evaluation" do
    let(:plugin_class) do
      Class.new(LogStash::Filters::Base)  do
        config_name "one_plugin"
        config :oneString, :validate => :string, :required => false
        config :oneBoolean, :validate => :boolean, :required => false
        config :oneNumber, :validate => :number, :required => false
        config :oneArray, :validate => :array, :required => false
        config :oneHash, :validate => :hash, :required => false
        config :nestedHash, :validate => :hash, :required => false
        config :nestedArray, :validate => :hash, :required => false
        config :deepHash, :validate => :hash, :required => false

        def initialize(params)
          super(params)
        end
      end
    end

    context "when an environment variable is not set" do
      context "and no default is given" do
        before do
          # Canary. Just in case somehow this is set.
          expect(ENV["NoSuchVariable"]).to be_nil
        end

        it "should raise a configuration error" do
          expect do
            plugin_class.new("oneString" => "${NoSuchVariable}")
          end.to raise_error(LogStash::ConfigurationError)
        end
      end

      context "and a default is given" do
        subject do
          plugin_class.new(
            "oneString" => "${notExistingVar:foo}",
            "oneBoolean" => "${notExistingVar:true}",
            "oneArray" => ["first array value", "${notExistingVar:foo}", "${notExistingVar:}", "${notExistingVar: }", "${notExistingVar:foo bar}"],
            "oneHash" => { "key" => "${notExistingVar:foo}" }
          )
        end

        it "should use the default" do
          expect(subject.oneString).to(be == "foo")
          expect(subject.oneBoolean).to be_truthy
          expect(subject.oneArray).to(be == ["first array value", "foo", "", " ", "foo bar"])
          expect(subject.oneHash).to(be == { "key" => "foo" })
        end
      end
    end

    context "when an environment variable is set" do
      before do
        ENV["FunString"] = "fancy"
        ENV["FunBool"] = "true"
        ENV["SERVER_LS_TEST_ADDRESS"] = "some.host.address.tld"
      end

      after do
        ENV.delete("FunString")
        ENV.delete("FunBool")
        ENV.delete("SERVER_LS_TEST_ADDRESS")
      end

      subject do
        plugin_class.new(
          "oneString" => "${FunString:foo}",
          "oneBoolean" => "${FunBool:false}",
          "oneArray" => ["first array value", "${FunString:foo}"],
          "oneHash" => { "key1" => "${FunString:foo}", "key2" => "${FunString} is ${FunBool}", "key3" => "${FunBool:false} or ${funbool:false}" },
          "nestedHash" => { "level1" => { "key1" => "http://${FunString}:8080/blah.txt" } },
          "nestedArray" => { "level1" => [{ "key1" => "http://${FunString}:8080/blah.txt" }, { "key2" => "http://${FunString}:8080/foo.txt" }] },
          "deepHash" => { "level1" => { "level2" => {"level3" => { "key1" => "http://${FunString}:8080/blah.txt" } } } }
        )
      end

      it "should use the value in the variable" do
        skip("This test fails on Windows, tracked in https://github.com/elastic/logstash/issues/10454")
        expect(subject.oneString).to(be == "fancy")
        expect(subject.oneBoolean).to(be_truthy)
        expect(subject.oneArray).to(be == ["first array value", "fancy"])
        expect(subject.oneHash).to(be == { "key1" => "fancy", "key2" => "fancy is true", "key3" => "true or false" })
        expect(subject.nestedHash).to(be == { "level1" => { "key1" => "http://fancy:8080/blah.txt" } })
        expect(subject.nestedArray).to(be == { "level1" => [{ "key1" => "http://fancy:8080/blah.txt" }, { "key2" => "http://fancy:8080/foo.txt" }] })
        expect(subject.deepHash).to(be == { "level1" => { "level2" => { "level3" => { "key1" => "http://fancy:8080/blah.txt" } } } })
      end

      it "should validate settings after interpolating ENV variables" do
        expect {
          Class.new(LogStash::Filters::Base) do
            include LogStash::Config::Mixin
            config_name "test"
            config :server_address, :validate => :uri
          end.new({"server_address" => "${SERVER_LS_TEST_ADDRESS}"})
        }.not_to raise_error
      end
    end

    context "should support $ in values" do
      before do
        ENV["bar"] = "foo"
        ENV["f$$"] = "bar"
      end

      after do
        ENV.delete("bar")
        ENV.delete("f$$")
      end

      subject do
        plugin_class.new(
          "oneString" => "${f$$:val}",
          "oneArray" => ["foo$bar", "${bar:my$val}"]
          # "dollar_in_env" => "${f$$:final}"
        )
      end

      it "should support $ in values" do
        expect(subject.oneArray).to(be == ["foo$bar", "foo"])
      end

      it "should not support $ in environment variable name" do
        expect(subject.oneString).to(be == "${f$$:val}")
      end
    end
  end
end
