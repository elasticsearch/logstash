# Encoding: utf-8
require_relative "../spec_helper"

describe "bin/logstash-plugin uninstall" do
  context "when the plugin isn't installed" do
    it "fails to uninstall it" do
      result = command("bin/logstash-plugin uninstall logstash-filter-cidr")
      expect(result.stderr).to match(/ERROR: Uninstall Aborted, message: This plugin has not been previously installed, aborting/)
      expect(result.exit_status).to eq(1)
    end
  end

  context "when the plugin is installed" do
      it "succesfully uninstall it" do
      # make sure we have the plugin installed.
      command("bin/logstash-plugin install logstash-filter-ruby")

      result = command("bin/logstash-plugin uninstall logstash-filter-ruby")

      expect(result.stdout).to match(/^Uninstalling logstash-filter-ruby/)
      expect(result.exit_status).to eq(0)
    end

    it "fails if has dependencies" do
      result  = command("bin/plugin uninstall logstash-input-tcp")
      message = "logstash-input-tcp is a dependency of logstash-input-graphite."
      expect(result.stderr).to match(/ERROR: Uninstall Aborted, message: #{message}/)
      expect(result.exit_status).to eq(1)
    end
  end
end
