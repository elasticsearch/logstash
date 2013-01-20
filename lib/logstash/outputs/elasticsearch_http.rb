require "logstash/namespace"
require "logstash/outputs/base"

# This output lets you store logs in elasticsearch.
#
# This plugin uses the HTTP/REST interface to ElasticSearch, which usually
# lets you use any version of elasticsearch server. It is known to work
# with elasticsearch %ELASTICSEARCH_VERSION%
#
# You can learn more about elasticsearch at <http://elasticsearch.org>
class LogStash::Outputs::ElasticSearchHTTP < LogStash::Outputs::Base

  config_name "elasticsearch_http"
  plugin_status "beta"

  # The index to write events to. This can be dynamic using the %{foo} syntax.
  # The default value will partition your indices by day so you can more easily
  # delete old data or only search specific date ranges.
  config :index, :validate => :string, :default => "logstash-%{+YYYY.MM.dd}"

  # The index type to write events to. Generally you should try to write only
  # similar events to the same 'type'. String expansion '%{foo}' works here.
  config :index_type, :validate => :string, :default => "%{@type}"

  # The name/address of the host to use for ElasticSearch unicast discovery
  # This is only required if the normal multicast/cluster discovery stuff won't
  # work in your environment.
  config :host, :validate => :string

  # The port for ElasticSearch transport to use. This is *not* the ElasticSearch
  # REST API port (normally 9200).
  config :port, :validate => :number, :default => 9200

  # Set the number of events to queue up before writing to elasticsearch.
  #
  # If this value is set to 1, the normal ['index
  # api'](http://www.elasticsearch.org/guide/reference/api/index_.html).
  # Otherwise, the [bulk
  # api](http://www.elasticsearch.org/guide/reference/api/bulk.html) will
  # be used.
  config :flush_size, :validate => :number, :default => 100

  # The document ID for the index. Useful for overwriting existing entries in
  # elasticsearch with the same ID.
  config :document_id, :validate => :string, :default => nil

  # this will enable automatic node discovery and random selection on each bulk index operation
  config :bulk_discovery, :validate => :boolean, :default => false
  config :bulk_discovery_refresh, :validate => :number, :default => 60

  public
  def register
    require "ftw" # gem ftw
    @agent = FTW::Agent.new
    @queue = []
    @http_transports = []

    if @bulk_discovery
      @http_transports = get_http_transports

      @bulk_discovery_thread = Thread.new do
        while sleep(@bulk_discovery_refresh) do
          @http_transports = get_http_transports
        end
      end
    end

  end # def register

  public
  def receive(event)
    return unless output?(event)

    index = event.sprintf(@index)
    type = event.sprintf(@index_type)

    if @flush_size == 1
      receive_single(event, index, type)
    else
      receive_bulk(event, index, type)
    end # 
  end # def receive

  def receive_single(event, index, type)
    success = false
    while !success
      response = @agent.post!("http://#{@host}:#{@port}/#{index}/#{type}",
                              :body => event.to_json)
      # We must read the body to free up this connection for reuse.
      body = "";
      response.read_body { |chunk| body += chunk }

      if response.status != 201
        @logger.error("Error writing to elasticsearch",
                      :response => response, :response_body => body)
      else
        success = true
      end
    end
  end # def receive_single

  def receive_bulk(event, index, type)
    header = { "index" => { "_index" => index, "_type" => type } }
    if !@document_id.nil?
      header["index"]["_id"] = event.sprintf(@document_id)
    end
    @queue << [
      header.to_json, event.to_json
    ].join("\n")

    # Keep trying to flush while the queue is full.
    # This will cause retries in flushing if the flush fails.
    flush while @queue.size >= @flush_size
  end # def receive_bulk

  def flush
    @logger.debug? && @logger.debug("Flushing events to elasticsearch",
                                    :count => @queue.count)
    # If we don't tack a trailing newline at the end, elasticsearch
    # doesn't seem to process the last event in this bulk index call.
    #
    # as documented here: 
    # http://www.elasticsearch.org/guide/reference/api/bulk.html
    #  "NOTE: the final line of data must end with a newline character \n."

    if @bulk_discovery
      host, port = @http_transports[rand(@http_transports.size)]
    else
      host = @host
      port = @port
    end

    response = @agent.post!("http://#{host}:#{port}/_bulk",
                            :body => @queue.join("\n") + "\n")

    # Consume the body for error checking
    # This will also free up the connection for reuse.
    body = ""
    response.read_body { |chunk| body += chunk }

    if response.status != 200
     if @bulk_discovery == false
       @logger.error("Error writing (bulk) to elasticsearch",
                    :response => response, :response_body => body,
                    :request_body => @queue.join("\n"))
     else
       @logger.error("Error writing (bulk) to elasticsearch",
                     :response => response)
       @logger.warn("Refreshing http transports")
       @http_transports = get_http_transports
     end

     return
    end

    # Clear the queue on success only.
    @queue.clear
  end # def flush

  def teardown
    flush while @queue.size > 0
  end # def teardown

  # THIS IS NOT USED YET. SEE LOGSTASH-592
  def setup_index_template
    template_name = "logstash-template"
    template_wildcard = @index.gsub(/%{[^}+]}/, "*")
    template_config = {
      "template" => template_wildcard,
      "settings" => {
        "number_of_shards" => 5,
        "index.compress.stored" => true,
        "index.query.default_field" => "@message"
      },
      "mappings" => {
        "_default_" => {
          "_all" => { "enabled" => false } 
        }
      }
    } # template_config

    @logger.info("Setting up index template", :name => template_name,
                 :config => template_config)
    begin
      success = false
      while !success
        response = @agent.put!("http://#{@host}:#{@port}/_template/#{template_name}",
                               :body => template_config.to_json)
        if response.error?
          body = ""
          response.read_body { |c| body << c }
          @logger.warn("Failure setting up elasticsearch index template, will retry...",
                       :status => response.status, :response => body)
          sleep(1)
        else
          success = true
        end
      end
    rescue => e
      @logger.warn("Failure setting up elasticsearch index template, will retry...",
                   :exception => e)
      sleep(1)
      retry
    end
  end # def setup_index_template

  def get_http_transports
    ret = []
    @http_transports << [@host, @port]

    while ret.empty?

      host, port = @http_transports[rand(@http_transports.size)]
      begin
        response = @agent.get!("http://#{host}:#{port}/_cluster/nodes")
        body = "";
        response.read_body { |chunk| body += chunk }
      rescue
        #probably conn refused
        @logger.warn("Failed to fet _cluster/nodes from #{host}:#{port}, will retry...")
      end

      if response.nil? or response.status != 200
        @logger.warn("Failed to fet _cluster/nodes from #{host}:#{port}, will retry...",
                        :status => response.status, :response => body)
        sleep(5)
      else

        JSON.parse(body)['nodes'].each do |id,data|
          #i don't want to buggy non data nodes on bulk uploads
          next if ( data['attributes'] && data['attributes']['data'] && (data['attributes']['data'] == "false"))

          if data['http_address']
            match = data['http_address'].match /^inet\[\/(.*):(\d+)\]$/
            ret << [ match[1], match[2] ]
          end
        end

        if ret.empty?
          @logger.warn("Fetched empty _cluster/nodes from #{host}:#{port}, will retry...",
          :status => response.status, :response => body)
          sleep(5)
        end

      end
    end

    return ret
  end

end # class LogStash::Outputs::ElasticSearchHTTP
