# Licensed to Elasticsearch B.V. under one or more contributor
# license agreements. See the NOTICE file distributed with
# this work for additional information regarding copyright
# ownership. Elasticsearch B.V. licenses this file to you under
# the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

module ::LogStash; module Plugins; module Builtin; module Pipeline; class Output < ::LogStash::Outputs::Base
  include org.logstash.plugins.pipeline.PipelineOutput

  config_name "pipeline"

  concurrency :shared

  config :send_to, :validate => :string, :required => true, :list => true

  config :ensure_delivery, :validate => :boolean, :default => true

  attr_reader :pipeline_bus

  def register
    @pipeline_bus = execution_context.agent.pipeline_bus
    # add list of pipelines to send to the plugin metrics
    metric.gauge(:send_to, send_to)
    pipeline_bus.registerSender(self, @send_to)
  end

  def multi_receive(events)
    pipeline_bus.sendEvents(self, events, ensure_delivery)
  end

  def close
    puts "Unregistering #{self} from #{@send_to}"
    pipeline_bus.unregisterSender(self, @send_to)
  end
end; end; end; end; end