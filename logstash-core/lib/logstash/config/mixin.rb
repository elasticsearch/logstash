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

require "logstash/util/password"
require "logstash/util/safe_uri"
require "logstash/version"
require "logstash/environment"
require "logstash/util/plugin_version"
require "logstash/codecs/delegator"
require "filesize"

LogStash::Environment.load_locale!

# This module is meant as a mixin to classes wishing to be configurable from
# config files
#
# The idea is that you can do this:
#
# class Foo < LogStash::Config
#   # Add config file settings
#   config "path" => ...
#   config "tag" => ...
#
#   # Add global flags (becomes --foo-bar)
#   flag "bar" => ...
# end
#
# And the config file should let you do:
#
# foo {
#   "path" => ...
#   "tag" => ...
# }
#
module LogStash::Config::Mixin
  include LogStash::Util::SubstitutionVariables
  include LogStash::Util::Loggable

  attr_accessor :config
  attr_accessor :original_params

  # This method is called when someone does 'include LogStash::Config'
  def self.included(base)
    # Add the DSL methods to the 'base' given.
    base.extend(LogStash::Config::Mixin::DSL)
  end

  def config_init(params)
    # Validation will modify the values inside params if necessary.
    # For example: converting a string to a number, etc.

    # Keep a copy of the original config params so that we can later
    # differentiate between explicit configuration and implicit (default)
    # configuration.
    original_params = params.clone

    # store the plugin type, turns LogStash::Inputs::Base into 'input'
    @plugin_type = self.class.ancestors.find { |a| a.name =~ /::Base$/ }.config_name

    # Set defaults from 'config :foo, :default => somevalue'
    self.class.get_config.each do |name, opts|
      next if params.include?(name.to_s)
      if opts.include?(:default) and (name.is_a?(Symbol) or name.is_a?(String))
        # default values should be cloned if possible
        # cloning prevents
        case opts[:default]
          when FalseClass, TrueClass, NilClass, Numeric
            params[name.to_s] = opts[:default]
          else
            params[name.to_s] = opts[:default].clone
        end
      end

      # Allow plugins to override default values of config settings
      if self.class.default?(name)
        params[name.to_s] = self.class.get_default(name)
      end
    end

    # Resolve environment variables references
    params.each do |name, value|
      params[name.to_s] = deep_replace(value, true)
    end

    # Intercept codecs that have not been instantiated
    params.each do |name, value|
      validator = self.class.validator_find(name)
      next unless validator && validator[:validate] == :codec && value.kind_of?(String)

      codec_klass = LogStash::Plugin.lookup("codec", value)
      codec_instance = LogStash::Plugins::Contextualizer.initialize_plugin(execution_context, codec_klass)

      params[name.to_s] = LogStash::Codecs::Delegator.new(codec_instance)
    end

    if !self.class.validate(params)
      raise LogStash::ConfigurationError,
        I18n.t("logstash.runner.configuration.invalid_plugin_settings")
    end

    # now that we know the parameters are valid, we can obfuscate the original copy
    # of the parameters before storing them as an instance variable
    self.class.secure_params!(original_params)
    @original_params = original_params

    # warn about deprecated variable use
    original_params.each do |name, value|
      opts = self.class.get_config[name]
      if opts && opts[:deprecated]
        extra = opts[:deprecated].is_a?(String) ? opts[:deprecated] : ""
        extra.gsub!("%PLUGIN%", self.class.config_name)
        self.deprecation_logger.deprecated(
          "You are using a deprecated config setting #{name.inspect} set in " \
          "#{self.class.config_name}. Deprecated settings will continue to work, " \
          "but are scheduled for removal from logstash in the future. #{extra} " \
          "If you have any questions about this, please ask it on the " \
          "https://discuss.elastic.co/c/logstash discussion forum",
          {}
        )
      end

      if opts && opts[:obsolete]
        extra = opts[:obsolete].is_a?(String) ? opts[:obsolete] : ""
        extra.gsub!("%PLUGIN%", self.class.config_name)
        raise LogStash::ConfigurationError,
          I18n.t("logstash.runner.configuration.obsolete", :name => name,
                 :plugin => self.class.config_name, :extra => extra)
      end
    end

    # We remove any config options marked as obsolete,
    # no code should be associated to them and their values should not bleed
    # to the plugin context.
    #
    # This need to be done after fetching the options from the parents class
    params.reject! do |name, value|
      opts = self.class.get_config[name]
      opts.include?(:obsolete)
    end

    # set instance variables like '@foo'  for each config value given.
    params.each do |key, value|
      next if key[0, 1] == "@"

      # Set this key as an instance variable only if it doesn't start with an '@'
      self.logger.debug("config #{self.class.name}/@#{key} = #{value.inspect}")
      instance_variable_set("@#{key}", value)
    end

    @config = params
  end # def config_init

  module DSL
    include LogStash::Util::SubstitutionVariables

    attr_accessor :flags

    # If name is given, set the name and return it.
    # If no name given (nil), return the current name.
    def config_name(name = nil)
      @config_name = name if !name.nil?
      @config_name
    end
    alias_method :config_plugin, :config_name

    # Deprecated: Declare the version of the plugin
    # inside the gemspec.
    def plugin_status(status = nil)
      milestone(status)
    end

    # Deprecated: Declare the version of the plugin
    # inside the gemspec.
    def milestone(m = nil)
      self.logger.debug(I18n.t('logstash.plugin.deprecated_milestone', :plugin => config_name))
    end

    # Define a new configuration setting
    #
    # @param name [String, Symbol, Regexp]
    # @param opts [Hash]: the options for this config parameter
    # @option opts [Array,Symbol] :validate
    #   When `Array`, the expanded form of the given directive MUST exist in the Array.
    #   When `Symbol`, the named validator matching the provided `Symbol` is used.
    # @option opts [Boolean]      :list
    # @option opts [Object]       :default
    # @option opts [Boolean]      :required
    def config(name, opts = {})
      @config ||= Hash.new
      # TODO(sissel): verify 'name' is of type String, Symbol, or Regexp

      name = name.to_s if name.is_a?(Symbol)
      @config[name] = opts  # ok if this is empty

      if name.is_a?(String) && opts.fetch(:attr_accessor, true)
        define_method(name) { instance_variable_get("@#{name}") }
        define_method("#{name}=") { |v| instance_variable_set("@#{name}", v) }
      end
    end # def config

    def default(name, value)
      @defaults ||= {}
      @defaults[name.to_s] = value
    end

    def get_config
      return @config
    end # def get_config

    def get_default(name)
      return @defaults && @defaults[name]
    end

    def default?(name)
      return @defaults && @defaults.include?(name)
    end

    def options(opts)
      # add any options from this class
      prefix = self.name.split("::").last.downcase
      @flags.each do |flag|
        flagpart = flag[:args].first.gsub(/^--/, "")
        # TODO(sissel): logger things here could help debugging.

        opts.on("--#{prefix}-#{flagpart}", *flag[:args][1..-1], &flag[:block])
      end
    end # def options

    # This is called whenever someone subclasses a class that has this mixin.
    def inherited(subclass)
      # Copy our parent's config to a subclass.
      # This method is invoked whenever someone subclasses us, like:
      # class Foo < Bar ...
      subconfig = Hash.new
      if !@config.nil?
        @config.each do |key, val|
          subconfig[key] = val
        end
      end
      subclass.instance_variable_set("@config", subconfig)
    end # def inherited

    def validate(params)
      @plugin_name = config_name
      @plugin_type = ancestors.find { |a| a.name =~ /::Base$/ }.config_name
      is_valid = true

      is_valid &&= validate_check_invalid_parameter_names(params)
      is_valid &&= validate_check_required_parameter_names(params)
      is_valid &&= validate_check_parameter_values(params)

      return is_valid
    end # def validate

    def validate_check_invalid_parameter_names(params)
      invalid_params = params.keys
      # Filter out parameters that match regexp keys.
      # These are defined in plugins like this:
      #   config /foo.*/ => ...
      @config.each_key do |config_key|
        if config_key.is_a?(Regexp)
          invalid_params.reject! { |k| k =~ config_key }
        elsif config_key.is_a?(String)
          invalid_params.reject! { |k| k == config_key }
        end
      end

      if invalid_params.size > 0
        invalid_params.each do |name|
          self.logger.error("Unknown setting '#{name}' for #{@plugin_name}")
        end
        return false
      end # if invalid_params.size > 0
      return true
    end # def validate_check_invalid_parameter_names

    def validate_check_required_parameter(config_key, config_opts, k, v)
      if config_key.is_a?(Regexp)
        (k =~ config_key && v)
      elsif config_key.is_a?(String)
        k && v
      end
    end

    def validate_check_required_parameter_names(params)
      is_valid = true

      @config.each do |config_key, config|
        next unless config[:required]

        if config_key.is_a?(Regexp) && !params.keys.any? { |k| k =~ config_key }
          is_valid = false
        end

        value = params[config_key]
        if value.nil? || (config[:list] && Array(value).empty?)
          self.logger.error(I18n.t("logstash.runner.configuration.setting_missing",
                               :setting => config_key, :plugin => @plugin_name,
                               :type => @plugin_type))
          is_valid = false
        end
      end

      return is_valid
    end

    def process_parameter_value(value, config_settings)
      config_val = config_settings[:validate]

      if config_settings[:list]
        value = Array(value) # coerce scalars to lists
        # Empty lists are converted to nils
        return true, [] if value.empty?

        return validate_value(value, :uri_list) if config_val == :uri

        validated_items = value.map {|v| validate_value(v, config_val)}
        is_valid = validated_items.all? {|sr| sr[0] }
        processed_value = validated_items.map {|sr| sr[1]}
      else
        is_valid, processed_value = validate_value(value, config_val)
      end

      return [is_valid, processed_value]
    end

    def validate_check_parameter_values(params)
      # Filter out parameters that match regexp keys.
      # These are defined in plugins like this:
      #   config /foo.*/ => ...
      all_params_valid = true

      params.each do |key, value|
        @config.keys.each do |config_key|
          next unless (config_key.is_a?(Regexp) && key =~ config_key) \
                      || (config_key.is_a?(String) && key == config_key)

          config_settings = @config[config_key]

          is_valid, processed_value = process_parameter_value(value, config_settings)

          if is_valid
            # Accept coerced value if valid
            # Used for converting values in the config to proper objects.
            params[key] = processed_value
          else
            self.logger.error(I18n.t("logstash.runner.configuration.setting_invalid",
                                 :plugin => @plugin_name, :type => @plugin_type,
                                 :setting => key, :value => value.inspect,
                                 :value_type => config_settings[:validate],
                                 :note => processed_value))
          end

          all_params_valid &&= is_valid

          break # done with this param key
        end # config.each
      end # params.each

      return all_params_valid
    end # def validate_check_parameter_values

    def validator_find(key)
      @config.each do |config_key, config_val|
        if (config_key.is_a?(Regexp) && key =~ config_key) \
           || (config_key.is_a?(String) && key == config_key)
          return config_val
        end
      end # @config.each
      return nil
    end

    ##
    # Performs deep replacement of the provided value, then performs validation and coercion.
    #
    # The provided validator can be nil, an Array of acceptable values, or a Symbol
    # representing a named validator, and is the result of a configuration parameter's `:validate` option (@see DSL#config)
    #
    # @overload validate_value(value, validator)
    #   Validation occurs with the named validator.
    #   @param value [Object]
    #   @param validator [Symbol]
    # @overload validate_value(value, validator)
    #   The value must exist in the provided Array.
    #   @param value [Object]
    #   @param validator [Array]
    # @overload validate_value(value, validator)
    #   The value is always considered valid
    #   @param value [Object]
    #   @param validator [nil]
    #
    # @return [Array<(true, Object)>]: when value is valid, a tuple containing true and a coerced form of the value is returned
    # @return [Array<(false, String)>]: when value is not valid, a tuple containing false and an error string is returned.
    #
    # @api private
    #
    # WARNING: validators added here must be back-ported to the Validation Support plugin mixin so that plugins
    #          that use them are not constrained to the version of Logstash that introduced the validator.
    def validate_value(value, validator)
      # Validator comes from the 'config' pieces of plugins.
      # They look like this
      #   config :mykey => lambda do |value| ... end
      # (see LogStash::Inputs::File for example)
      result = nil

      value = deep_replace(value)

      if validator.nil?
        return true, value
      elsif validator.is_a?(Array)
        value = [*value]
        if value.size > 1
          return false, "Expected one of #{validator.inspect}, got #{value.inspect}"
        end

        if !validator.include?(value.first)
          return false, "Expected one of #{validator.inspect}, got #{value.inspect}"
        end
        result = value.first
      elsif validator.is_a?(Symbol)
        # TODO(sissel): Factor this out into a coercion method?
        # TODO(sissel): Document this stuff.
        value = hash_or_array(value)

        case validator
          when :codec
            if value.first.is_a?(String)
              # A plugin's codecs should be instantiated by `PluginFactory` or in `Config::Mixin#config_init(Hash)`,
              # which ensure the inner plugin has access to the outer's execution context and metric store.
              # This deprecation exists to warn plugins that call `Config::Mixin::validate_value` directly.
              self.deprecation_logger.deprecated("Codec instantiated by `Config::Mixin::DSL::validate_value(String, :codec)` which cannot propagate parent plugin's execution context or metrics. ",
                                                 self.logger.debug? ? {:backtrace => caller} : {})
              value = LogStash::Codecs::Delegator.new LogStash::Plugin.lookup("codec", value.first).new
              return true, value
            else
              value = value.first
              return true, value
            end
          when :hash
            if value.is_a?(Hash)
              return true, value
            end

            if value.size % 2 == 1
              return false, "This field must contain an even number of items, got #{value.size}"
            end

            # Convert the array the config parser produces into a hash.
            result = {}
            value.each_slice(2) do |key, value|
              entry = result[key]
              if entry.nil?
                result[key] = value
              else
                if entry.is_a?(Array)
                  entry << value
                else
                  result[key] = [entry, value]
                end
              end
            end
          when :array
            result = value
          when :string
            if value.size > 1 # only one value wanted
              return false, "Expected string, got #{value.inspect}"
            end
            result = value.first.to_s
          when :number
            if value.size > 1 # only one value wanted
              return false, "Expected number, got #{value.inspect} (type #{value.class})"
            end

            v = value.first
            case v
              when Numeric
                result = v
              when String
                if v.to_s.to_f.to_s != v.to_s \
                   && v.to_s.to_i.to_s != v.to_s
                  return false, "Expected number, got #{v.inspect} (type #{v})"
                end
                if v.include?(".")
                  # decimal value, use float.
                  result = v.to_f
                else
                  result = v.to_i
                end
            end # case v
          when :boolean
            if value.size > 1 # only one value wanted
              return false, "Expected boolean, got #{value.inspect}"
            end

            bool_value = value.first
            if !!bool_value == bool_value
              # is_a does not work for booleans
              # we have Boolean and not a string
              result = bool_value
            else
              if bool_value !~ /^(true|false)$/
                return false, "Expected boolean 'true' or 'false', got #{bool_value.inspect}"
              end

              result = (bool_value == "true")
            end
          when :ipaddr
            if value.size > 1 # only one value wanted
              return false, "Expected IPaddr, got #{value.inspect}"
            end

            octets = value.split(".")
            if octets.length != 4
              return false, "Expected IPaddr, got #{value.inspect}"
            end
            octets.each do |o|
              if o.to_i < 0 or o.to_i > 255
                return false, "Expected IPaddr, got #{value.inspect}"
              end
            end
            result = value.first
          when :password
            if value.size > 1
              return false, "Expected password (one value), got #{value.size} values?"
            end

            result = value.first.is_a?(::LogStash::Util::Password) ? value.first : ::LogStash::Util::Password.new(value.first.to_s)
          when :uri
            if value.size > 1
              return false, "Expected uri (one value), got #{value.size} values?"
            end

            result = value.first.is_a?(::LogStash::Util::SafeURI) ? value.first : ::LogStash::Util::SafeURI.new(value.first)
          when :uri_list
            # expand entries that have space-delimited URIs in strings.
            # This validator is considered private, and can be accessed
            # by specifying `:validate => :uri` and `:list => true`
            result = value.flat_map do |entry|
              entry.kind_of?(String) ? entry.split(' ') : entry
            end.map do |expanded_entry|
              ::LogStash::Util::SafeURI.from(expanded_entry)
            end
          when :path
            if value.size > 1 # Only 1 value wanted
              return false, "Expected path (one value), got #{value.size} values?"
            end

            # Paths must be absolute
            #if !Pathname.new(value.first).absolute?
              #return false, "Require absolute path, got relative path #{value.first}?"
            #end

            if !File.exist?(value.first) # Check if the file exists
              return false, "File does not exist or cannot be opened #{value.first}"
            end

            result = value.first
          when :bytes
            begin
              bytes = Integer(value.first) rescue nil
              result = bytes || Filesize.from(value.first).to_i
            rescue ArgumentError
              return false, "Unparseable filesize: #{value.first}. possible units (KiB, MiB, ...) e.g. '10 KiB'. doc reference: http://www.elastic.co/guide/en/logstash/current/configuration.html#bytes"
            end
          when :field_reference # @since 7.11
            return [false, "Expected exactly one field reference, got `#{value.inspect}`"] unless value.kind_of?(Array) && value.size <= 1
            return [true, nil] if value.empty? || value.first.nil? || value.first.empty?

            candidate = value.first

            return [false, "Expected a valid field reference, got `#{candidate.inspect}`"] unless org.logstash.FieldReference.isValid(candidate)

            return [true, candidate]
          when :sha_256_hex # since 8.3
            return [false, "Expected exactly one hex-encoded SHA-256 fingerprint, got `#{value.inspect}`"] unless value.kind_of?(Array) && value.size <= 1
            return [true, nil] if value.empty? || value.first.nil? || value.first.empty?

            candidate = value.first

            return [false, "Expected a hex-encoded SHA-256 fingerprint, got `#{candidate.inspect}`"] unless candidate.kind_of?(String) && candidate =~ /\A(?:[[:xdigit:]]{2}:?){32}\z/

            return [true, candidate.upcase.tr('^0-9A-F', '')]
          else
            return false, "Unknown validator symbol #{validator}"
        end # case validator
      else
        return false, "Unknown validator #{validator.class}"
      end

      # Return the validator for later use, like with type coercion.
      return true, result
    end # def validate_value

    def secure_params!(params)
      params.each do |key, value|
        if [:uri, :password].include? @config[key][:validate]
          is_valid, processed_value = process_parameter_value(value, @config[key])
          params[key] = processed_value
        end
      end
    end

    def hash_or_array(value)
      if !value.is_a?(Hash)
        value = [*value] # coerce scalar to array if necessary
      end
      return value
    end
  end # module LogStash::Config::DSL
end # module LogStash::Config
