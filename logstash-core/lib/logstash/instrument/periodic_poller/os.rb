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

require "logstash/instrument/periodic_poller/base"
require "logstash/instrument/periodic_poller/cgroup"

module LogStash module Instrument module PeriodicPoller
  class Os < Base
    def initialize(metric, options = {})
      super(metric, options)
    end

    def collect
      collect_cgroup
    end

    def collect_cgroup
      # try cgroup v2 first and fallback to cgroup v1
      if stats = CgroupV2.get
        save_metric([:os], :cgroup, stats)
      elsif stats = Cgroup.get
        save_metric([:os], :cgroup, stats)
      end
    end

    # Recursive function to create the Cgroups values form the created hash
    def save_metric(namespace, k, v)
      if v.is_a?(Hash)
        v.each do |new_key, new_value|
          n = namespace.dup
          n << k.to_sym
          save_metric(n, new_key, new_value)
        end
      else
        metric.gauge(namespace, k.to_sym, v)
      end
    end
  end
end; end; end
