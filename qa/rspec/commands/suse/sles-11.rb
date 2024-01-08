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

require_relative "../base"
require_relative "../suse"

module ServiceTester
  class Sles11Commands < SuseCommands

    def running?(package)
      stdout = ""
      cmd = sudo_exec!("/etc/init.d/#{package} status")
      stdout = cmd.stdout
      stdout.match(/#{package} is running$/)
    end

<<<<<<< HEAD
    def service_manager(service, action, host=nil)
      hosts = (host.nil? ? servers : Array(host))
      at(hosts, {in: :serial}) do |_|
        sudo_exec!("/etc/init.d/#{service} #{action}")
      end
=======
    def service_manager(service, action)
      sudo_exec!("/etc/init.d/#{service} #{action}")
>>>>>>> cebe4a753 (Refactor qa/acceptance tests to get away from vagrant (#15696))
    end
  end
end
