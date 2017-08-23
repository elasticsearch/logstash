# encoding: utf-8
require "logstash/namespace"
require "base64"

module LogStash module Util class CloudId
  attr_reader :original, :decoded, :label, :elasticsearch_host, :kibana_host

  def initialize(value)
    return if value.nil?

    unless value.is_a?(String)
      raise ArgumentError.new("Cloud Id must be String. Received: #{value.class}")
    end
    @original = value
    @label, sep, last = value.partition(":")
    if last.empty?
      @decoded = Base64.urlsafe_decode64(@label) rescue ""
      @label = ""
    else
      @decoded = Base64.urlsafe_decode64(last) rescue ""
    end
    unless @decoded.count("$") == 2
      raise ArgumentError.new("Cloud Id does not decode. Received: \"#{@original}\".")
    end
    cloud_host, es_server, kb_server = @decoded.split("$")
    @elasticsearch_host = sprintf("%s.%s:443", es_server, cloud_host)
    @kibana_host  = sprintf("%s.%s:443", kb_server, cloud_host)
  end
end end end