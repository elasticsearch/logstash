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

#require "gems"

# This patch is necessary to avoid encoding problems when Net:HTTP return stuff in ASCII format, but
# consumer libraries, like the YAML parsers expect them to be in UTF-8. As we're using UTF-8 everywhere
# and the usage of versions is minimal in our codebase, the patch is done here. If extended usage of this
# is done in the feature, more proper fix should be implemented, including the creation of our own lib for
# this tasks.
module Gems
  module Request
    def get(path, data = {}, content_type = 'application/x-www-form-urlencoded', request_host = host)
      request(:get, path, data, content_type, request_host).force_encoding("UTF-8")
    end
  end
end

module ::Bundler
  class Thor
    class Arguments
      def parse_array(name)
        return shift if peek.is_a?(Array)
        array = []
        array << shift while current_is_value?
        array
      end
    end
  end
end
