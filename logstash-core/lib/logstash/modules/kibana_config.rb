# encoding: utf-8
require "logstash/namespace"
require "logstash/logging"

require_relative "file_reader"
require_relative "kibana_settings"
require_relative "kibana_dashboards"
require_relative "kibana_resource"

module LogStash module Modules class KibanaConfig
  include LogStash::Util::Loggable

  ALLOWED_DIRECTORIES = ["search", "visualization"]

  METRICS_MAX_BUCKETS = (24 * 60 * 60).freeze # 24 hours of events/sec buckets.
  attr_reader :index_name # not used when importing via kibana but for BWC with ElastsearchConfig

  # We name it `modul` here because `module` has meaning in Ruby.
  def initialize(modul, settings)
    @name = modul.module_name
    @settings = settings
    @index_name = settings.fetch("dashboards.kibana_index", ".kibana")
    @directory = ::File.join(modul.directory, "kibana")
    @pattern_name = "#{@name}-*"
    @metrics_max_buckets = @settings.fetch("dashboards.metrics_max_buckets", METRICS_MAX_BUCKETS).to_i
    @kibana_settings = [
      KibanaSettings::Setting.new("defaultIndex", @pattern_name),
      KibanaSettings::Setting.new("metrics:max_buckets", @metrics_max_buckets)
    ]
  end

  def dashboards
    # there can be more than one dashboard to load
    puts "*"*10
    puts dynamic("dashboard")
    puts "*"*10
    filenames = FileReader.read_json(dynamic("dashboard"))
    filenames.map do |filename|
      KibanaResource.new(@index_name, "dashboard", dynamic("dashboard", filename))
    end
  end

  def index_pattern
    [KibanaResource.new(@index_name, "index-pattern", dynamic("index-pattern"),nil, @pattern_name)]
  end

  def resources
    list = index_pattern
    dashboards.each do |board|
      list << board
      extract_panels_into(board, list)
    end
    list.concat(extract_saved_searches_into(list))
    [
      KibanaSettings.new("api/kibana/settings", @kibana_settings),
      KibanaDashboards.new("api/kibana/dashboards/import", list)
    ]
  end

  private

  def dynamic(dynamic_folder, filename = @name)
    ::File.join(@directory, dynamic_folder, "#{filename}.json")
  end

  def extract_panels_into(dashboard, list)
    dash = dashboard.content_as_object

    if !dash.is_a?(Hash)
      logger.warn("Kibana dashboard JSON is not an Object", :module => @name)
      return
    end

    panelsjson = dash["panelsJSON"]

    if panelsjson.nil?
      logger.info("No panelJSON key found in kibana dashboard", :module => @name)
      return
    end

    begin
      panels = LogStash::Json.load(panelsjson)
    rescue => e
      logger.error("JSON parse error when reading kibana panelsJSON", :module => @name)
      return
    end

    panels.each do |panel|
      panel_type = panel["type"]
      if ALLOWED_DIRECTORIES.member?(panel_type)
        list << KibanaResource.new(@index_name, panel_type, dynamic(panel_type, panel["id"]))
      else
        logger.warn("panelJSON contained unknown type", :type => panel_type)
      end
    end
  end

  def extract_saved_searches_into(list)
    result = [] # must not add to list while iterating
    list.each do |resource|
      content = resource.content_as_object
      next if content.nil?
      next unless content.keys.include?("savedSearchId")
      saved_search = content["savedSearchId"]
      next if saved_search.nil?
      ss_resource = KibanaResource.new(@index_name, "search", dynamic("search", saved_search))
      next if list.member?(ss_resource) || result.member?(ss_resource)
      result << ss_resource
    end
    result
  end
end end end
