# encoding: utf-8
require "spec_helper"
require "logstash/plugin"
require "logstash/outputs/base"
require "logstash/codecs/base"
require "logstash/inputs/base"
require "logstash/filters/base"

describe "slowlog interface" do

  let(:logger) { double("logger") }
  let(:config) { {} }

  [LogStash::Inputs::Base, LogStash::Filters::Base, LogStash::Outputs::Base].each do |plugin_base|

    subject(:plugin) do
      Class.new(plugin_base,) do
        config_name "dummy"
      end.new(config)
    end

    let(:event) { LogStash::Event.new }

    it "should respond to slow_logger" do
      expect(plugin.respond_to?(:slow_logger=)).to eq(true)
      expect(plugin.respond_to?(:slow_logger)).to  eq(true)
    end

    describe LogStash::Plugin::Timer do

      it "should respond to timer" do
        expect(plugin.respond_to?(:timer)).to eq(true)
      end

      it "should enable timinig operations" do
        plugin.timer.start
        sleep 0.1
        expect(plugin.timer.stop).to be > 0
      end
    end

  end

  describe LogStash::Logging::SlowLogger do

    subject { described_class.new }
    let(:event) { LogStash::Event.new }

    it "should respond to log" do
      expect(subject.respond_to?(:log)).to eq(true)
    end

    describe "notify slow operations" do
      let(:logger) { double("logger") }

      before(:each) do
        allow(logger).to receive(:warn)
        subject.logger = logger
      end

      context "when the threshold is not defined" do
        it "should not report" do
          expect(logger).not_to receive(:warn)
          subject.log(event, "not.defined.op", 9)
        end
      end

      context "when the threshold is defined" do

        before(:each) do
          expect(subject).to receive(:setting).with("your.op").and_return(15)
        end

        it "should not report to the logger if not overcome" do
          expect(logger).not_to receive(:warn)
          subject.log(event, "your.op", 14)
        end

        it "should report to the logger if overcome" do
          expect(logger).to receive(:warn)
          subject.log(event, "your.op", 16)
        end
      end
    end

  end
end
