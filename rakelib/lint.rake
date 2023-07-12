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

namespace "lint" do

  module RubocopCLI
    def self.run!(*args)
      require "rubocop"
      cli = RuboCop::CLI.new
      result = cli.run(["--display-cop-names", "--force-exclusion", "--fail-level", "autocorrect", *args])
      raise "Linting failed." if result.nonzero?
    end
  end

  # task that runs lint report
  task "report" do
    require 'rubocop'
    cli = RuboCop::CLI.new
    # cli.run(["--display-cop-names", "--force-exclusion", "--fail-level", "autocorrect"])
    #cli.run(["--display-cop-names", "--force-exclusion", "--lint"])
    #cli.run(["--lint"])
    RubocopCLI.run!("--lint")
  end

  # task that automatically fixes code formatting
  task "format" do
    #require 'rubocop'
    #cli = RuboCop::CLI.new
    #cli.run(["--fix-layout"])
    RubocopCLI.run!("--fix-layout")
  end
end
