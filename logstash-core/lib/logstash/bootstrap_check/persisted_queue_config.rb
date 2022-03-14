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

java_import 'org.logstash.common.FsUtil'
java_import 'java.nio.file.Paths'
java_import "java.nio.file.FileStore"
java_import "java.nio.file.Files"

module LogStash
  module BootstrapCheck
    module PersistedQueueConfig
      extend self

      # Check the config of persistent queue. Raise BootstrapCheckError if fail the check.
      def check(running_pipelines, pipeline_configs)
        return unless queue_configs_updated?(running_pipelines, pipeline_configs)

        err_msg = []
        queue_path_file_system = Hash.new # (String: queue path, String: file system)
        required_free_bytes  = Hash.new # (String: file system, Integer: size)

        pipeline_configs.select { |config| config.settings.get('queue.type') == 'persisted'}
                        .select { |config| config.settings.get('queue.max_bytes').to_i != 0 }
                        .each do |config|
          max_bytes = config.settings.get("queue.max_bytes").to_i
          page_capacity = config.settings.get("queue.page_capacity").to_i
          pipeline_id = config.settings.get("pipeline.id")
          queue_path = config.settings.get("path.queue")
          pq_page_glob = ::File.join(queue_path, pipeline_id, "page.*")
          used_bytes = get_page_size(pq_page_glob)
          file_system = get_file_system(queue_path)

          check_page_capacity(err_msg, pipeline_id, max_bytes, page_capacity)
          check_queue_usage(err_msg, pipeline_id, max_bytes, used_bytes)

          queue_path_file_system[queue_path] = file_system
          if used_bytes < max_bytes
            required_free_bytes[file_system] = required_free_bytes.fetch(file_system, 0) + max_bytes - used_bytes
          end
        end

        check_disk_space(err_msg, queue_path_file_system, required_free_bytes)

        raise(LogStash::BootstrapCheckError, err_msg.flatten.join(" ")) unless err_msg.empty?
      end

      def check_page_capacity(err_msg, pipeline_id, max_bytes, page_capacity)
        if page_capacity > max_bytes
          err_msg << "Pipeline #{pipeline_id} 'queue.page_capacity' must be less than or equal to 'queue.max_bytes'."
        end
      end

      def check_queue_usage(err_msg, pipeline_id, max_bytes, used_bytes)
        if used_bytes > max_bytes
          err_msg << "Pipeline #{pipeline_id} current queue size (#{used_bytes}) is greater than 'queue.max_bytes' (#{max_bytes})."
        end
      end

      # Check disk has sufficient space for all queues reach their max bytes. Queues may config with different paths/ devices.
      # It uses the filesystem of the path and count the required bytes by filesystem
      def check_disk_space(err_msg, queue_path_file_system, required_free_bytes)
        disk_err_msg =
          queue_path_file_system
            .select { |queue_path, file_system| !FsUtil.hasFreeSpace(Paths.get(queue_path), required_free_bytes.fetch(file_system, 0)) }
            .map { |queue_path, file_system| "Persistent queue path #{queue_path} is unable to allocate #{required_free_bytes.fetch(file_system, 0)} more bytes on top of its current usage." }

        err_msg << disk_err_msg unless disk_err_msg.empty?
      end

      def get_file_system(queue_path)
        fs = Files.getFileStore(Paths.get(queue_path));
        fs.name
      end

      # PQ page size in bytes
      def get_page_size(page_glob)
        ::Dir.glob(page_glob).sum { |f| ::File.size(f) }
      end

      # Compare value in pipeline registry and new pipeline config
      # return true if new pipeline is added or reloadable PQ config has changed
      # running_pipelines: Map of {pipeline_id (sym) => JavaPipeline}
      # pipeline_configs: Array of PipelineConfig
      def queue_configs_updated?(running_pipelines, pipeline_configs)
        pipeline_configs.each do |pipeline_config|
          return true unless running_pipelines.has_key?(pipeline_config.pipeline_id.to_sym)

          settings = running_pipelines.fetch(pipeline_config.pipeline_id.to_sym).settings
          return true unless settings.get_value("queue.type") == pipeline_config.settings.get("queue.type") &&
            settings.get_value("queue.max_bytes") == pipeline_config.settings.get("queue.max_bytes") &&
            settings.get_value("queue.page_capacity") == pipeline_config.settings.get("queue.page_capacity") &&
            settings.get_value("path.queue") == pipeline_config.settings.get("path.queue")
        end

        false
      end
    end
  end
end
