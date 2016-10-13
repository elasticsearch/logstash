module LogStash
  module RakeLib

    # plugins included by default in the logstash distribution
    DEFAULT_PLUGINS = %w(
      logstash-input-heartbeat
      logstash-codec-collectd
      logstash-codec-dots
      logstash-codec-edn
      logstash-codec-avro
      logstash-codec-edn_lines
      logstash-codec-fluent
      logstash-codec-es_bulk
      logstash-codec-graphite
      logstash-codec-json
      logstash-codec-json_lines
      logstash-codec-line
      logstash-codec-msgpack
      logstash-codec-multiline
      logstash-codec-netflow
      logstash-codec-plain
      logstash-codec-rubydebug
      logstash-filter-csv
      logstash-filter-date
      logstash-filter-dns
      logstash-filter-drop
      logstash-filter-fingerprint
      logstash-filter-geoip
      logstash-filter-grok
      logstash-filter-json
      logstash-filter-kv
      logstash-filter-metrics
      logstash-filter-mutate
      logstash-filter-ruby
      logstash-filter-sleep
      logstash-filter-split
      logstash-filter-syslog_pri
      logstash-filter-throttle
      logstash-filter-uuid
      logstash-filter-urldecode
      logstash-filter-useragent
      logstash-filter-xml
      logstash-input-couchdb_changes
      logstash-input-elasticsearch
      logstash-input-exec
      logstash-input-file
      logstash-input-imap
      logstash-input-ganglia
      logstash-input-gelf
      logstash-input-generator
      logstash-input-graphite
      logstash-input-http
      logstash-input-http_poller
      logstash-input-jdbc
      logstash-input-rabbitmq
      logstash-input-redis
      logstash-input-s3
      logstash-input-snmptrap
      logstash-input-sqs
      logstash-input-stdin
      logstash-input-syslog
      logstash-input-tcp
      logstash-input-twitter
      logstash-input-udp
      logstash-input-kafka
      logstash-input-beats
      logstash-output-csv
      logstash-output-elasticsearch
      logstash-output-file
      logstash-output-graphite
      logstash-output-http
      logstash-output-kafka
      logstash-output-nagios
      logstash-output-null
      logstash-output-pagerduty
      logstash-output-rabbitmq
      logstash-output-redis
      logstash-output-s3
      logstash-output-stdout
      logstash-output-tcp
      logstash-output-udp
      logstash-output-webhdfs
    )

    # plugins required to run the logstash core specs
    CORE_SPECS_PLUGINS = %w(
      logstash-filter-clone
      logstash-filter-mutate
      logstash-filter-multiline
      logstash-input-generator
      logstash-input-stdin
      logstash-input-tcp
      logstash-output-stdout
    )

    TEST_JAR_DEPENDENCIES_PLUGINS = %w(
      logstash-input-kafka
    )

    TEST_VENDOR_PLUGINS = %w(
      logstash-codec-collectd
    )

    ALL_PLUGINS_SKIP_LIST = Regexp.union([
      /^logstash-filter-yaml$/,
      /example$/,
      /drupal/i,
      /^logstash-output-logentries$/,
      /^logstash-output-newrelic$/,
      /^logstash-output-slack$/,
      /^logstash-input-neo4j$/,
      /^logstash-output-neo4j$/,
      /^logstash-input-perfmon$/,
      /^logstash-output-webhdfs$/,
      /^logstash-input-rackspace$/,
      /^logstash-output-rackspace$/,
      /^logstash-input-dynamodb$/,
      /^logstash-filter-language$/,
      /^logstash-input-heroku$/,
      /^logstash-output-google_cloud_storage$/,
      /^logstash-input-journald$/,
      /^logstash-input-log4j2$/,
      /^logstash-codec-cloudtrail$/
    ])


    # @return [Array<String>] list of all plugin names as defined in the logstash-plugins github organization, minus names that matches the ALL_PLUGINS_SKIP_LIST
    def self.fetch_all_plugins
      require 'octokit'
      Octokit.auto_paginate = true
      repos = Octokit.organization_repositories("logstash-plugins")
      repos.map(&:name).reject do |name|
        name =~ ALL_PLUGINS_SKIP_LIST || !is_released?(name)
      end
    end

    def self.is_released?(plugin)
      require 'gems'
      Gems.info(plugin) != "This rubygem could not be found."
    end
  end
end
