# encoding: utf-8

require "spec_helper"
require "logstash/util"
require "logstash/event"
require "json"
require "java"

TIMESTAMP = "@timestamp"

describe LogStash::Event do
  context "to_json" do
    it "should correctly serialize RubyNil values a Null values" do
      e = LogStash::Event.new({ "null_value" => nil, TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      expect(JSON.parse(e.to_json)).to eq(JSON.parse("{\"null_value\":null,\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}"))
    end

    it "should serialize simple values" do
      e = LogStash::Event.new({"foo" => "bar", "bar" => 1, "baz" => 1.0, TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      expect(JSON.parse(e.to_json)).to eq(JSON.parse("{\"foo\":\"bar\",\"bar\":1,\"baz\":1.0,\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}"))
    end

    it "should serialize deep hash values" do
      e = LogStash::Event.new({"foo" => {"bar" => 1, "baz" => 1.0, "biz" => "boz"}, TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      expect(JSON.parse(e.to_json)).to eq(JSON.parse("{\"foo\":{\"bar\":1,\"baz\":1.0,\"biz\":\"boz\"},\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}"))
    end

    it "should serialize deep array values" do
      e = LogStash::Event.new({"foo" => ["bar", 1, 1.0], TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      expect(JSON.parse(e.to_json)).to eq(JSON.parse("{\"foo\":[\"bar\",1,1.0],\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\"}"))
    end

    it "should serialize deep hash from field reference assignments" do
      e = LogStash::Event.new({TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      e.set("foo", "bar")
      e.set("bar", 1)
      e.set("baz", 1.0)
      e.set("[fancy][pants][socks]", "shoes")
      expect(JSON.parse(e.to_json)).to eq(JSON.parse("{\"@timestamp\":\"2015-05-28T23:02:05.350Z\",\"@version\":\"1\",\"foo\":\"bar\",\"bar\":1,\"baz\":1.0,\"fancy\":{\"pants\":{\"socks\":\"shoes\"}}}"))
    end
  end

  context "#get" do
    it "should get simple values" do
      e = LogStash::Event.new({"foo" => "bar", "bar" => 1, "baz" => 1.0, TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      expect(e.get("foo")).to eq("bar")
      expect(e.get("[foo]")).to eq("bar")
      expect(e.get("bar")).to eq(1)
      expect(e.get("[bar]")).to eq(1)
      expect(e.get("baz")).to eq(1.0)
      expect(e.get("[baz]")).to eq(1.0)
      expect(e.get(TIMESTAMP).to_s).to eq("2015-05-28T23:02:05.350Z")
      expect(e.get("[#{TIMESTAMP}]").to_s).to eq("2015-05-28T23:02:05.350Z")
    end

    it "should get deep hash values" do
      e = LogStash::Event.new({"foo" => {"bar" => 1, "baz" => 1.0}})
      expect(e.get("[foo][bar]")).to eq(1)
      expect(e.get("[foo][baz]")).to eq(1.0)
    end

    it "should get deep array values" do
      e = LogStash::Event.new({"foo" => ["bar", 1, 1.0]})
      expect(e.get("[foo][0]")).to eq("bar")
      expect(e.get("[foo][1]")).to eq(1)
      expect(e.get("[foo][2]")).to eq(1.0)
      expect(e.get("[foo][3]")).to be_nil
    end

    context "negative array values" do
      it "should index from the end of the array" do
        list = ["bar", 1, 1.0]
        e = LogStash::Event.new({"foo" => list})
        expect(e.get("[foo][-3]")).to eq(list[-3])
        expect(e.get("[foo][-2]")).to eq(list[-2])
        expect(e.get("[foo][-1]")).to eq(list[-1])
      end
    end
  end

  context "#set" do
    it "should set simple values" do
      e = LogStash::Event.new()
      expect(e.set("foo", "bar")).to eq("bar")
      expect(e.get("foo")).to eq("bar")

      e = LogStash::Event.new({"foo" => "test"})
      expect(e.set("foo", "bar")).to eq("bar")
      expect(e.get("foo")).to eq("bar")
    end
  
    it "should propagate changes to mutable strings to java APIs" do
      e = LogStash::Event.new()
      e.to_java.setField("foo", "bar")
      expect(e.get("foo")).to eq("bar")
      e.get("foo").gsub!(/bar/, 'pff')
      expect(e.get("foo")).to eq("pff")
      expect(e.to_java.getField("foo")).to eq("pff")
    end

    it "should set deep hash values" do
      e = LogStash::Event.new()
      expect(e.set("[foo][bar]", "baz")).to eq("baz")
      expect(e.get("[foo][bar]")).to eq("baz")
      expect(e.get("[foo][baz]")).to be_nil
    end

    it "should set deep array values" do
      e = LogStash::Event.new()
      expect(e.set("[foo][0]", "bar")).to eq("bar")
      expect(e.get("[foo][0]")).to eq("bar")
      expect(e.set("[foo][1]", 1)).to eq(1)
      expect(e.get("[foo][1]")).to eq(1)
      expect(e.set("[foo][2]", 1.0)).to eq(1.0)
      expect(e.get("[foo][2]")).to eq(1.0)
      expect(e.get("[foo][3]")).to be_nil
    end

    it "should add key when setting nil value" do
      e = LogStash::Event.new()
      e.set("[foo]", nil)
      expect(e.to_hash).to include("foo" => nil)
    end

    # BigDecimal is now natively converted by JRuby, see https://github.com/elastic/logstash/pull/4838
    it "should set BigDecimal" do
      e = LogStash::Event.new()
      e.set("[foo]", BigDecimal.new(1))
      expect(e.get("foo")).to be_kind_of(BigDecimal)
      expect(e.get("foo")).to eq(BigDecimal.new(1))
    end

    it "should set RubyBignum" do
      e = LogStash::Event.new()
      e.set("[foo]", -9223372036854776000)
      expect(e.get("foo")).to be_kind_of(Bignum)
      expect(e.get("foo")).to eq(-9223372036854776000)
    end

    it "should convert Time to Timestamp" do
      e = LogStash::Event.new()
      time = Time.now
      e.set("[foo]", Time.at(time.to_f))
      expect(e.get("foo")).to be_kind_of(LogStash::Timestamp)
      expect(e.get("foo").to_f).to be_within(0.1).of(time.to_f)
    end

    it "should set XXJavaProxy Jackson crafted" do
      proxy = org.logstash.RspecTestUtils.getMapFixtureJackson()
      # proxy is {"string": "foo", "int": 42, "float": 42.42, "array": ["bar","baz"], "hash": {"string":"quux"} }
      e = LogStash::Event.new()
      e.set("[proxy]", proxy)
      expect(e.get("[proxy][string]")).to eql("foo")
      expect(e.get("[proxy][int]")).to eql(42)
      expect(e.get("[proxy][float]")).to eql(42.42)
      expect(e.get("[proxy][array][0]")).to eql("bar")
      expect(e.get("[proxy][array][1]")).to eql("baz")
      expect(e.get("[proxy][hash][string]")).to eql("quux")
    end

    it "should set XXJavaProxy hand crafted" do
      proxy = org.logstash.RspecTestUtils.getMapFixtureHandcrafted()
      # proxy is {"string": "foo", "int": 42, "float": 42.42, "array": ["bar","baz"], "hash": {"string":"quux"} }
      e = LogStash::Event.new()
      e.set("[proxy]", proxy)
      expect(e.get("[proxy][string]")).to eql("foo")
      expect(e.get("[proxy][int]")).to eql(42)
      expect(e.get("[proxy][float]")).to eql(42.42)
      expect(e.get("[proxy][array][0]")).to eql("bar")
      expect(e.get("[proxy][array][1]")).to eql("baz")
      expect(e.get("[proxy][hash][string]")).to eql("quux")
    end

    it "should fail on non UTF-8 encoding" do
      # e = LogStash::Event.new
      # s1 = "\xE0 Montr\xE9al".force_encoding("ISO-8859-1")
      # expect(s1.encoding.name).to eq("ISO-8859-1")
      # expect(s1.valid_encoding?).to eq(true)
      # e.set("test", s1)
      # s2 = e.get("test")
      # expect(s2.encoding.name).to eq("UTF-8")
      # expect(s2.valid_encoding?).to eq(true)
    end
  end

  context "timestamp" do
    it "getters should present a Ruby LogStash::Timestamp" do
      e = LogStash::Event.new()
      expect(e.timestamp.class).to eq(LogStash::Timestamp)
      expect(e.get(TIMESTAMP).class).to eq(LogStash::Timestamp)
    end

    it "to_hash should inject a Ruby LogStash::Timestamp" do
      e = LogStash::Event.new()

      expect(e.to_java).to be_kind_of(Java::OrgLogstash::Event)
      expect(e.to_java.get_field(TIMESTAMP)).to be_kind_of(Java::OrgLogstash::Timestamp)

      expect(e.to_hash[TIMESTAMP]).to be_kind_of(LogStash::Timestamp)
      # now make sure the original map was not touched
      expect(e.to_java.get_field(TIMESTAMP)).to be_kind_of(Java::OrgLogstash::Timestamp)
    end

    it "should set timestamp" do
      e = LogStash::Event.new
      now = Time.now
      e.set("@timestamp", LogStash::Timestamp.at(now.to_i))
      expect(e.timestamp.to_i).to eq(now.to_i)
      expect(e.get("@timestamp").to_i).to eq(now.to_i)
    end
  end

  context "append" do
    it "should append" do
      event = LogStash::Event.new("message" => "hello world")
      event.append(LogStash::Event.new("message" => "another thing"))
      expect(event.get("message")).to eq(["hello world", "another thing"])
    end
  end

  context "tags" do
    it "should tag" do
      event = LogStash::Event.new("message" => "hello world")
      expect(event.get("tags")).to be_nil
      event.tag("foo")
      expect(event.get("tags")).to eq(["foo"])
    end
  end


  # TODO(talevy): migrate tests to Java. no reason to test logging logic in ruby when it is being
  #               done in java land.

  # context "logger" do

  #   let(:logger) { double("Logger") }

  #   before(:each) do
  #     allow(LogStash::Event).to receive(:logger).and_return(logger)
  #   end

  #   it "should set logger using a module" do
  #     expect(logger).to receive(:warn).once
  #     LogStash::Event.new(TIMESTAMP => "invalid timestamp")
  #   end

  #   it "should warn on invalid timestamp object" do
  #     expect(logger).to receive(:warn).once.with(/^Unrecognized/)
  #     LogStash::Event.new(TIMESTAMP => Array.new)
  #   end
  # end

  context "to_hash" do
    let (:source_hash) {  {"a" => 1, "b" => [1, 2, 3, {"h" => 1, "i" => "baz"}], "c" => {"d" => "foo", "e" => "bar", "f" => [4, 5, "six"]}} }
    let (:source_hash_with_metadata) {  source_hash.merge({"@metadata" => {"a" => 1, "b" => 2}}) }
    subject { LogStash::Event.new(source_hash_with_metadata) }

    it "should include @timestamp and @version" do
      h = subject.to_hash
      expect(h).to include("@timestamp")
      expect(h).to include("@version")
      expect(h).not_to include("@metadata")
    end

    it "should include @timestamp and @version and @metadata" do
      h = subject.to_hash_with_metadata
      expect(h).to include("@timestamp")
      expect(h).to include("@version")
      expect(h).to include("@metadata")
    end

    it "should produce valid deep Ruby hash without metadata" do
      h = subject.to_hash
      h.delete("@timestamp")
      h.delete("@version")
      expect(h).to eq(source_hash)
    end

    it "should produce valid deep Ruby hash with metadata" do
      h = subject.to_hash_with_metadata
      h.delete("@timestamp")
      h.delete("@version")
      expect(h).to eq(source_hash_with_metadata)
    end
  end

  context "from_json" do
    let (:source_json) { "{\"foo\":1, \"bar\":\"baz\"}" }
    let (:blank_strings) {["", "  ",  "   "]}
    let (:bare_strings) {["aa", "  aa", "aa  "]}

    it "should produce a new event from json" do
      expect(LogStash::Event.from_json(source_json).size).to eq(1)

      event = LogStash::Event.from_json(source_json)[0]
      expect(event.get("[foo]")).to eq(1)
      expect(event.get("[bar]")).to eq("baz")
    end

    it "should ignore blank strings" do
      blank_strings.each do |s|
        expect(LogStash::Event.from_json(s).size).to eq(0)
      end
    end

    it "should raise TypeError on nil string" do
      expect{LogStash::Event.from_json(nil)}.to raise_error TypeError
    end

    it "should consistently handle nil" do
      blank_strings.each do |s|
        expect{LogStash::Event.from_json(nil)}.to raise_error
        expect{LogStash::Event.new(LogStash::Json.load(nil))}.to raise_error
      end
    end

    it "should consistently handle bare string" do
      bare_strings.each do |s|
        expect{LogStash::Event.from_json(s)}.to raise_error LogStash::Json::ParserError
        expect{LogStash::Event.new(LogStash::Json.load(s))}.to raise_error LogStash::Json::ParserError
       end
    end
  end

  context "initialize" do

    it "should accept Ruby Hash" do
      e = LogStash::Event.new({"foo" => 1, TIMESTAMP => "2015-05-28T23:02:05.350Z"})
      expect(e.get("foo")).to eq(1)
      expect(e.timestamp.to_iso8601).to eq("2015-05-28T23:02:05.350Z")
    end

    it "should accept Java Map" do
      h = Java::JavaUtil::HashMap.new
      h.put("foo", 2);
      h.put(TIMESTAMP, "2016-05-28T23:02:05.350Z");
      e = LogStash::Event.new(h)

      expect(e.get("foo")).to eq(2)
      expect(e.timestamp.to_iso8601).to eq("2016-05-28T23:02:05.350Z")
    end

  end

  context "method missing exception messages" do
    subject { LogStash::Event.new({"foo" => "bar"}) }

    it "#[] method raises a better exception message" do
      expect { subject["foo"] }.to raise_error(NoMethodError, /Direct event field references \(i\.e\. event\['field'\]\)/)
    end

    it "#[]= method raises a better exception message" do
      expect { subject["foo"] = "baz" }.to raise_error(NoMethodError, /Direct event field references \(i\.e\. event\['field'\] = 'value'\)/)
    end

    it "other missing method raises normal exception message" do
      expect { subject.baz() }.to raise_error(NoMethodError, /undefined method `baz' for/)
    end
  end

  describe "#clone" do
    let(:fieldref) { "[@metadata][fancy]" }
    let(:event1) { LogStash::Event.new("hello" => "world", "@metadata" => { "fancy" => "pants" }) }
    let(:event2) { LogStash::Event.new("hello" => "world", "@metadata" => { "fancy" => {"fancy2" => "pants2"} }) }
    let(:event3) { LogStash::Event.new("hello" => "world", "@metadata" => { "fancy" => {"fancy2" => {"fancy3" => "pants2"}} }) }
    let(:event4) { LogStash::Event.new("hello" => "world", "@metadata" => { "fancy" => {"fancy2" => ["pants1", "pants2"]} }) }
    let(:event5) { LogStash::Event.new("hello" => "world", "@metadata" => { "fancy" => "pants", "smarty" => "pants2" }) }

    it "should clone metadata fields" do
      cloned = event1.clone
      expect(cloned.get(fieldref)).to eq("pants")
      expect(cloned.to_hash_with_metadata).to include("@metadata")
    end

    it "should clone metadata fields with nested json" do
      cloned = event2.clone
      expect(cloned.get(fieldref)).to eq({"fancy2" => "pants2"})
      expect(cloned.get("hello")).to eq("world")
      expect(cloned.to_hash).not_to include("@metadata")
      expect(cloned.to_hash_with_metadata).to include("@metadata")
    end

    it "should clone metadata fields with 2-level nested json" do
      cloned = event3.clone
      expect(cloned.get(fieldref)).to eq({"fancy2" => {"fancy3" => "pants2"}})
      expect(cloned.to_hash).not_to include("@metadata")
      expect(cloned.to_hash_with_metadata).to include("@metadata")
    end

    it "should clone metadata fields with nested json and array value" do
      cloned = event4.clone
      expect(cloned.get(fieldref)).to eq({"fancy2" => ["pants1", "pants2"]})
      expect(cloned.to_hash_with_metadata).to include("@metadata")
    end

    it "should clone metadata fields with multiple keys" do
      cloned = event5.clone
      expect(cloned.get(fieldref)).to eq("pants")
      expect(cloned.get("[@metadata][smarty]")).to eq("pants2")
      expect(cloned.to_hash_with_metadata).to include("@metadata")
    end

    it "mutating cloned event should not affect the original event" do
      cloned = event1.clone
      cloned.set("hello", "foobar")
      expect(cloned.get("hello")).to eq("foobar")
      expect(event1.get("hello")).to eq("world")
    end

    it "mutating cloned event's metadata should not affect the original event metadata" do
      cloned = event1.clone
      cloned.set("[@metadata][fancy]", "foobar")
      expect(cloned.get("[@metadata][fancy]")).to eq("foobar")
      expect(event1.get("[@metadata][fancy]")).to eq("pants")
    end
  end

   describe "#event-UTF" do
    it "should set and get values for non-ASCII keys" do
#      e = LogStash::Event.new()
#      expect(e.set("фуу", "bar")).to eq("bar")
#      expect(e.get("фуу")).to eq("bar")

#      e = LogStash::Event.new({"фуу" => "test"})
#      expect(e.set("фуу", "bar")).to eq("bar")
#      expect(e.get("фуу")).to eq("bar")
    end

    it "should set and get values for non-ASCII keys through java APIs" do
      e = LogStash::Event.new()
      e.to_java.setField("фуу", "bar")
      expect(e.get("фуу")).to eq("bar")
      e.get("фуу").gsub!(/bar/, 'pff')
      expect(e.get("фуу")).to eq("pff")
      expect(e.to_java.getField("фуу")).to eq("pff")
    end

  end

end
