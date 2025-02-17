Gem::Specification.new do |gem|
  gem.authors       = ["Logstash"]
  gem.email         = ["info@elastic.co"]
  gem.description   = "Logstash beats input benchmarking client"
  gem.summary       = gem.description
  gem.homepage      = "https://github.com/elastic/logstash"

  gem.files = Dir.glob("lib/**/*.rb")

  gem.test_files    = Dir.glob("spec/**/*.rb")
  gem.name          = "beats-benchmark"
  gem.require_paths = ["lib"]
  gem.version       = "0.0.1"

  gem.add_runtime_dependency "jls-lumberjack"
end