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

# Logic from elasticsearch/core/src/main/java/org/elasticsearch/monitor/os/OsProbe.java
# Move to ruby to remove any existing dependency
module LogStash module Instrument module PeriodicPoller
  class Cgroup
    include LogStash::Util::Loggable
    class Override
      attr_reader :key, :value

      def initialize(key)
        @key = key
        @value = java.lang.System.getProperty(@key)
      end

      def nil?
        value.nil?
      end

      def override(other)
        nil? ? other : value
      end
    end

    ## `/proc/self/cgroup` contents look like this
    # 5:cpu,cpuacct:/
    # 4:cpuset:/
    # 2:net_cls,net_prio:/
    # 0::/user.slice/user-1000.slice/session-932.scope
    ## e.g. N:controller:/path-to-info
    # we find the controller and path
    # we skip the line without a controller e.g. 0::/path
    # we assume there are these symlinks:
    # `/sys/fs/cgroup/cpu` -> `/sys/fs/cgroup/cpu,cpuacct
    # `/sys/fs/cgroup/cpuacct` -> `/sys/fs/cgroup/cpu,cpuacct

    CGROUP_FILE = "/proc/self/cgroup"
    CPUACCT_DIR = "/sys/fs/cgroup/cpuacct"
    CPU_DIR = "/sys/fs/cgroup/cpu"
    CRITICAL_PATHS = [CGROUP_FILE, CPUACCT_DIR, CPU_DIR]

    CONTROLLER_CPUACCT_LABEL = "cpuacct"
    CONTROLLER_CPU_LABEL = "cpu"

    class CGroupResources
      CONTROL_GROUP_RE = Regexp.compile("\\d+:([^:,]+(?:,[^:,]+)?):(/.*)")
      CONTROLLER_SEPARATOR_RE = ","

      def cgroup_available?
        # don't cache to ivar, in case the files are mounted after logstash starts??
        CRITICAL_PATHS.all? {|path| ::File.exist?(path)}
      end

      def controller_groups
        response = {}
        IO.readlines(CGROUP_FILE).each do |line|
          matches = CONTROL_GROUP_RE.match(line)
          next if matches.nil?
          # multiples controls, same hierarchy
          controllers = matches[1].split(CONTROLLER_SEPARATOR_RE)
          controllers.each do |controller|
            case controller
            when CONTROLLER_CPU_LABEL
              response[controller] = CpuResource.new(matches[2])
            when CONTROLLER_CPUACCT_LABEL
              response[controller] = CpuAcctResource.new(matches[2])
            else
              response[controller] = UnimplementedResource.new(controller, matches[2])
            end
          end
        end
        response
      end
    end

    module ControllerResource
      attr_reader :base_path, :override, :offset_path

      def implemented?
        true
      end
      private
      def common_initialize(base, override_key, original_path)
        @base_path = base
        # override is needed here for the logging statements
        @override = Override.new(override_key)
        @offset_path = @override.override(original_path)
        @procs = {}
        @procs[:read_int] = lambda {|path| IO.readlines(path).first.to_i }
        @procs[:read_lines] = lambda {|path| IO.readlines(path) }
      end

      def call_if_file_exists(call_key, file, not_found_value)
        path = ::File.join(@base_path, @offset_path, file)
        if ::File.exist?(path)
          @procs[call_key].call(path)
        else
          message = "File #{path} cannot be found, "
          if override.nil?
            message.concat("try providing an override '#{override.key}' in the Logstash JAVA_OPTS environment variable")
          else
            message.concat("even though the '#{override.key}' override is: '#{override.value}'")
          end
          logger.debug(message)
          not_found_value
        end
      end
    end

    class CpuAcctResource
      include LogStash::Util::Loggable
      include ControllerResource
      def initialize(original_path)
        common_initialize(CPUACCT_DIR, "ls.cgroup.cpuacct.path.override", original_path)
      end

      def to_hash
        {:control_group => offset_path, :usage_nanos => cpuacct_usage}
      end
      private
      def cpuacct_usage
        call_if_file_exists(:read_int, "cpuacct.usage", -1)
      end
    end

    class CpuResource
      include LogStash::Util::Loggable
      include ControllerResource
      def initialize(original_path)
        common_initialize(CPU_DIR, "ls.cgroup.cpu.path.override", original_path)
      end

      def to_hash
        {
          :control_group => offset_path,
          :cfs_period_micros => cfs_period_us,
          :cfs_quota_micros => cfs_quota_us,
          :stat => build_cpu_stats_hash
        }
      end
      private
      def cfs_period_us
        call_if_file_exists(:read_int, "cpu.cfs_period_us", -1)
      end

      def cfs_quota_us
        call_if_file_exists(:read_int, "cpu.cfs_quota_us", -1)
      end

      def build_cpu_stats_hash
        stats = CpuStats.new
        lines = call_if_file_exists(:read_lines, "cpu.stat", [])
        stats.update(lines)
        stats.to_hash
      end
    end

    class UnimplementedResource
      attr_reader :controller, :original_path

      def initialize(controller, original_path)
        @controller, @original_path = controller, original_path
      end

      def implemented?
        false
      end
    end

    class CpuStats
      def initialize
        @number_of_elapsed_periods = -1
        @number_of_times_throttled = -1
        @time_throttled_nanos = -1
      end

      def update(lines)
        lines.each do |line|
          fields = line.split(/\s+/)
          next unless fields.size > 1
          case fields.first
          when "nr_periods" then @number_of_elapsed_periods = fields[1].to_i
          when "nr_throttled" then @number_of_times_throttled = fields[1].to_i
          when "throttled_time" then @time_throttled_nanos = fields[1].to_i
          end
        end
      end

      def to_hash
        {
          :number_of_elapsed_periods => @number_of_elapsed_periods,
          :number_of_times_throttled => @number_of_times_throttled,
          :time_throttled_nanos => @time_throttled_nanos
        }
      end
    end

    CGROUP_RESOURCES = CGroupResources.new

    class << self
      def get_all
        unless CGROUP_RESOURCES.cgroup_available?
          logger.debug("One or more required cgroup files or directories not found: #{CRITICAL_PATHS.join(', ')}")
          return
        end

        groups = CGROUP_RESOURCES.controller_groups

        if groups.empty?
          logger.debug("The main cgroup file did not have any controllers: #{CGROUP_FILE}")
          return
        end

        cgroups_stats = {}
        groups.each do |name, controller|
          next unless controller.implemented?
          cgroups_stats[name.to_sym] = controller.to_hash
        end
        cgroups_stats
      rescue => e
        logger.debug("Error, cannot retrieve cgroups information", :exception => e.class.name, :message => e.message, :backtrace => e.backtrace.take(4)) if logger.debug?
        nil
      end

      def get
        get_all
      end
    end
  end

  ## cgroupv2 implementation
  class CgroupV2
    include LogStash::Util::Loggable

    ## `/proc/self/cgroup` contents look like this
    # 0::/
    # CPU statistics are still located in
    # - cpu.stat
    # CPU Limit is set within
    # - cpu.max
    # Memory Limit is set within
    # - memory.max
    # Memory Usage is set within
    # - memory.current

    CGROUP_FILE = "/proc/self/cgroup"
    BASE_PATH = "/sys/fs/cgroup"
    CPUSTAT_FILE = "cpu.stat"
    CPULIMIT_FILE = "cpu.max"
    MEMORY_LIMIT_FILE = "memory.max"
    MEMORY_USAGE_FILE = "memory.current"

    # exclude cpu.max. This could be missing
    CRITICAL_PATHS = [CPUSTAT_FILE, MEMORY_USAGE_FILE]

    class CGroupResources
      include LogStash::Util::Loggable

      def initialize
        @cgroup_path = "/"
      end

      def cgroup_available?
        all_lines = IO.readlines(CGROUP_FILE)
        if all_lines.size == 1 and all_lines[0][0,3] == "0::"
          @cgroup_path = all_lines[0].split(":")[2].chomp
          # CRITICAL_PATHS.each do |path|
          #   full_path = ::File.join(BASE_PATH, @cgroup_path, path)
          #   unless ::File.exists?(full_path)
          #     logger.debug("File #{full_path} does not exist")
          #   end
          # end
          CRITICAL_PATHS.all?{|path| ::File.exists?(::File.join(BASE_PATH, @cgroup_path, path))}
        else
          false
        end
      end

      def get_cpu_stats
        # read cpu.stat and cpu.max
        lines = IO.readlines(::File.join(BASE_PATH, @cgroup_path, CPUSTAT_FILE))
        stats = {}
        lines.each do |line|
          parts = line.chomp.split(/\s+/)
          stats[parts[0]] = parts[1].to_i
        end
        # read cpu.max
        if ::File.exists?(::File.join(BASE_PATH, @cgroup_path, CPULIMIT_FILE))
          lines = IO.readlines(::File.join(BASE_PATH, @cgroup_path, CPULIMIT_FILE))
          parts = lines[0].chomp.split(/\s+/)
          stats["quota_us"] = parts[0].to_i
          stats["period_us"] = parts[1].to_i
        end
        stats
      end

      def get_mem_stats
        stats = {}
        # read memory.current
        lines = IO.readlines(::File.join(BASE_PATH, @cgroup_path, MEMORY_USAGE_FILE))
        stats["memory_current"] = lines[0].chomp.to_i

        # read memory.max
        if ::File.exists?(::File.join(BASE_PATH, @cgroup_path, MEMORY_LIMIT_FILE))
          lines = IO.readlines(::File.join(BASE_PATH, @cgroup_path, MEMORY_LIMIT_FILE))
          stats["memory_limit"] = lines[0].chomp.to_i
        end
        stats
      end

      def get_stats(cpu_stats, memory_stats)
        stats = {}
        # we need to fake the final object to make the API compatible to cgroup v1 (and metricbeat)
        stats["cpuacct"] = {
          "control_group" => @cgroup_path,
          "usage_nanos" => cpu_stats.fetch("usage_usec", -1)
        }
        stats["cpu"] = {
          "control_group" => @cgroup_path,
          "cfs_period_micros" => cpu_stats.fetch("period_us", -1),
          "cfs_quota_micros" => cpu_stats.fetch("quota_us", -1),
          "stat" => {
            "number_of_elapsed_periods" => cpu_stats.fetch("nr_periods", -1),
            "number_of_times_throttled" => cpu_stats.fetch("nr_throttled", -1),
            "time_throttled_nanos" => cpu_stats.fetch("throttled_usec", -1)
          }
        }
        stats
      end
    end

    CGROUP_RESOURCES = CGroupResources.new

    class << self
      def get_all
        unless CGROUP_RESOURCES.cgroup_available?
          logger.debug("One or more required cgroup files or directories not found: #{CRITICAL_PATHS.join(', ')}")
          return
        end

        cpu_stats = CGROUP_RESOURCES.get_cpu_stats
        memory_stats = CGROUP_RESOURCES.get_mem_stats

        cgroups_stats = CGROUP_RESOURCES.get_stats(cpu_stats, memory_stats)
        cgroups_stats
      rescue => e
        logger.debug("Error, cannot retrieve cgroups information", :exception => e.class.name, :message => e.message, :backtrace => e.backtrace.take(4)) if logger.debug?
        nil
      end

      def get
        get_all
      end
    end
  end
end end end
