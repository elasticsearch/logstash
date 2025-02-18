Gem::Specification.new do |s|
  s.name            = File.basename(__FILE__, ".gemspec")
  s.version         = '0.1.1'
  s.licenses        = ['Apache-2.0']
  s.summary         = "A dummy plugin with two plugin dependencies"
  s.description     = "This plugin is only used in the acceptance test"
  s.authors         = ["Elasticsearch"]
  s.email           = 'info@elasticsearch.com'
  s.homepage        = "http://www.elasticsearch.org/guide/en/logstash/current/index.html"
  s.require_paths = ["lib"]

  # Files
  s.files = [__FILE__]

  # Tests
  s.test_files = []

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", ">= 1.60", "<= 2.99"

  s.add_runtime_dependency "logstash-filter-one_no_dependencies", "~> 0.1"
  s.add_runtime_dependency "logstash-filter-three_no_dependencies", "~> 0.1"
end
