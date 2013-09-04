require "logstash/codecs/base"

class LogStash::Codecs::OldLogStashJSON < LogStash::Codecs::Base
  config_name "oldlogstashjson"
  milestone 1

  public
  def decode(data)
    obj = JSON.parse(data.force_encoding("UTF-8"))

    h  = {}

    # Convert the old logstash schema to the new one.
    basics = %w(@message @source_host @source_path @source
                @tags @type)
    basics.each do |key|
      # Convert '@message' to 'message', etc
      h[key[1..-1]] = obj[key] if obj.include?(key)
    end

    h["@timestamp"] = obj["@timestamp"] if obj.include?("@timestamp")

    h.merge!(obj["@fields"]) if obj["@fields"].is_a?(Hash)
    yield LogStash::Event.new(h)
  end # def decode

  public
  def encode(data)
    h  = {}

    h["@timestamp"] = data["@timestamp"]
    h["@message"] = data["message"] if data.include?("message")
    h["@source_host"] = data["source_host"] if data.include?("source_host")
    # Convert the old logstash schema to the new one.
    basics = %w(@timestamp @message @source_host @source_path @source
                @tags @type)
    basics.each do |key|
      h[key] = obj[key] if obj.include?(key)
    end

    h.merge!(obj["@fields"]) if obj["@fields"].is_a?(Hash)
    @on_event.call(h)
  end # def encode

end # class LogStash::Codecs::OldLogStashJSON
