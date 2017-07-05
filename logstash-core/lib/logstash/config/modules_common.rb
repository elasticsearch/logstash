# encoding: utf-8
require "logstash/util/loggable"
require "logstash/elasticsearch_client"
require "logstash/modules/kibana_client"
require "logstash/modules/elasticsearch_importer"
require "logstash/modules/kibana_importer"
require "logstash/errors"

module LogStash module Config
  class ModulesCommon # extracted here for bwc with 5.x
    include LogStash::Util::Loggable

    def self.pipeline_configs(settings)
      pipelines = []
      plugin_modules = LogStash::PLUGIN_REGISTRY.plugins_with_type(:modules)

      modules_array = settings.get("modules.cli").empty? ? settings.get("modules") : settings.get("modules.cli")
      if modules_array.empty?
        # no specifed modules
        return pipelines
      end
      logger.debug("Specified modules", :modules_array => modules_array.to_s)

      module_names = modules_array.collect {|module_hash| module_hash["name"]}
      if module_names.length > module_names.uniq.length
        duplicate_modules = module_names.group_by(&:to_s).select { |_,v| v.size > 1 }.keys
        raise LogStash::ConfigLoadingError, I18n.t("logstash.modules.configuration.modules-must-be-unique", :duplicate_modules => duplicate_modules)
      end

      available_module_names = plugin_modules.map(&:module_name)
      specified_and_available_names = module_names & available_module_names

      if (specified_and_available_names).empty?
        i18n_opts = {:specified_modules => module_names, :available_modules => available_module_names}
        raise LogStash::ConfigLoadingError, I18n.t("logstash.modules.configuration.modules-unavailable", i18n_opts)
      end

      specified_and_available_names.each do |module_name|
        connect_fail_args = {}
        begin
          module_settings = settings.clone

          module_hash = modules_array.find {|m| m["name"] == module_name}
          current_module = plugin_modules.find { |allmodules| allmodules.module_name == module_name }

          alt_name = "module-#{module_name}"
          pipeline_id = alt_name
          module_settings.set("pipeline.id", pipeline_id)
          current_module.with_settings(module_hash)
          config_test = settings.get("config.test_and_exit")
          if !config_test
            esclient = LogStash::ElasticsearchClient.build(module_hash)
            kbnclient = LogStash::Modules::KibanaClient.new(module_hash)
            esconnected = esclient.can_connect?
            kbnconnected = kbnclient.can_connect?
            if esconnected && kbnconnected
              current_module.add_kibana_version(kbnclient.version_parts)
              current_module.import(
                  LogStash::Modules::ElasticsearchImporter.new(esclient),
                  LogStash::Modules::KibanaImporter.new(kbnclient)
                )
            else
              connect_fail_args[:module_name] = module_name
              connect_fail_args[:elasticsearch_hosts] = esclient.host_settings unless esconnected
              connect_fail_args[:kibana_hosts] = kbnclient.host_settings unless kbnconnected
            end
          end
          config_string = current_module.config_string
          pipelines << {"pipeline_id" => pipeline_id, "alt_name" => alt_name, "config_string" => config_string, "settings" => module_settings}
        rescue => e
          new_error = LogStash::ConfigLoadingError.new(I18n.t("logstash.modules.configuration.parse-failed", :error => e.message))
          new_error.set_backtrace(e.backtrace)
          raise new_error
        end

        if !connect_fail_args.empty?
          raise LogStash::ConfigLoadingError, I18n.t("logstash.modules.configuration.elasticsearch_connection_failed", connect_fail_args)
        end
      end
      pipelines
    end
  end
end end
