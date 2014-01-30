# encoding: utf-8
require "logstash/namespace"
require "logstash/event"
require "logstash/plugin"
require "logstash/logging"
require "logstash/config/mixin"
require "logstash/codecs/base"

# This is the base class for Logstash inputs.
class LogStash::Inputs::Base < LogStash::Plugin
  include LogStash::Config::Mixin
  config_name "input"

  # Add a 'type' field to all events handled by this input.
  #
  # Types are used mainly for filter activation.
  #
  # The type is stored as part of the event itself, so you can
  # also use the type to search for it in the web interface.
  #
  # If you try to set a type on an event that already has one (for
  # example when you send an event from a shipper to an indexer) then
  # a new input will not override the existing type. A type set at 
  # the shipper stays with that event for its life even
  # when sent to another Logstash server.
  config :type, :validate => :string

  # Set this to true to enable debugging on an input.
  config :debug, :validate => :boolean, :default => false

  # The codec used for input data
  config :codec, :validate => :codec, :default => "plain"

  # Add any number of arbitrary tags to your event.
  #
  # This can help with processing later.
  config :tags, :validate => :array

  # Add a field to an event
  config :add_field, :validate => :hash, :default => {}

  attr_accessor :params
  attr_accessor :threadable

  public
  def initialize(params={})
    super
    @threadable = false
    config_init(params)
    @tags ||= []
  end # def initialize

  public
  def register
    raise "#{self.class}#register must be overidden"
  end # def register

  public
  def tag(newtag)
    @tags << newtag
  end # def tag

  protected
  def to_event(raw, source) 
    raise LogStash::ThisMethodWasRemoved("LogStash::Inputs::Base#to_event - you should use codecs now instead of to_event. Not sure what this means? Get help on logstash-users@googlegroups.com!")
  end # def to_event

  protected
  def decorate(event)
    # Only set 'type' if not already set. This is backwards-compatible behavior
    event["type"] = @type if @type && !event.include?("type")

    if @tags.any?
      event["tags"] ||= []
      event["tags"] += @tags
    end

    @add_field.each do |field, value|
      event[field] = value
    end
  end
end # class LogStash::Inputs::Base
