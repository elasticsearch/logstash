# encoding: utf-8
require "logstash/namespace"
require "logstash/outputs/http"

#Shamelessly ripped off of the logstash/hipchat output.

# This output allows you to write events to [Zulip](https://www.zulip.com/).
#
class LogStash::Outputs::Zulip < LogStash::Outputs::Base

  config_name "zulip"
  milestone 1

  # The Zulip authentication bot username.
  config :botuser, :validate => :string, :required => true
  
  # The Zulip authentication key.
  config :key, :validate => :string, :required => true

  # type - stream or private.
  config :zuliptype, :validate => [ "stream", "private" ], :required => true

  # The Stream name / Private address
  config :to, :validate => :string, :required => true
  
  # The Stream subject
  config :subject, :validate => :string, :required => false
  
  # Message format to send, event tokens are usable here.
  config :format, :validate => :string, :default => "%{message}"

  public
  def register
    require 'net/https'
    require "uri"


    @url = "https://zulip.com/api/v1/messages"
    
    @zul_uri = URI.parse(@url)
    @client = Net::HTTP.new(@zul_uri.host, @zul_uri.port)
    if @zul_uri.scheme == "https"
      @client.use_ssl = true
      #@client.verify_mode = OpenSSL::SSL::VERIFY_PEER
      # PagerDuty cert doesn't verify oob
      @client.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end
    
  end # def register

  public
  def receive(event)
    return unless output?(event)

    @logger.info("Zulip message", :zulip_message => event.sprintf(@format))

    begin
      request = Net::HTTP::Post.new(@zul_uri.path)
      request.basic_auth(@botuser, @key)
      
      if @zuliptype == 'stream'
        request.set_form_data({'type' => 'stream', 'to' => @to, 'subject' => @subject, 'content' =>  event.sprintf(@format)})
      elsif @zuliptype == 'private'
        request.set_form_data({'type' => 'private', 'to' => @to ,'content' =>  event.sprintf(@format)})
      end
      
      @logger.debug("Zulip Request", :request => request.inspect)
      response = @client.request(request)
      @logger.debug("Zulip Response", :response => response.body)
    rescue Exception => e
      @logger.debug("Zulip Unhandled exception", :zulip_error => e.backtrace)
    end
  end # def receive
end # class LogStash::Outputs::Zulip