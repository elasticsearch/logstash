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

module LogStash module PluginManager module Utils
  class HttpClient
    class RedirectionLimit < RuntimeError; end

    HTTPS_SCHEME = "https"
    REDIRECTION_LIMIT = 5

    def self.start(uri)
      uri = URI(uri)
      proxy_url = ENV["https_proxy"] || ENV["HTTPS_PROXY"] || ""
      proxy_uri = URI(proxy_url)

      http = Net::HTTP.new(uri.host, uri.port, proxy_uri.host, proxy_uri.port, proxy_uri.user, proxy_uri.password)
      http.use_ssl(uri.scheme == HTTPS_SCHEME)
      http.open_timeout(10)
      http.start { |h| yield h }
    end

    # Do a HEAD request on the file to see if it exist before downloading it
    def self.remote_file_exist?(uri, redirect_count = 0)
      uri = URI(uri)

      # This is defensive programming, but in the real world we do create redirects all the time
      raise RedirectionLimit, "Too many redirection, tried #{REDIRECTION_LIMIT} times" if redirect_count >= REDIRECTION_LIMIT

      start(uri) do |http|
        return false if uri.path.empty?

        request = Net::HTTP::Head.new(uri.path)
        response = http.request(request)

        if response.code == "302"
          new_uri = response["location"]
          remote_file_exist?(new_uri, redirect_count + 1)
        elsif response.code == "200"
          true
        else
          false
        end
      end
    end
  end
end end end
