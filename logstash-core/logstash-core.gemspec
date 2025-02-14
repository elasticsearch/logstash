# -*- encoding: utf-8 -*-

# NOTE: please use `rake artifact:gems` or `rake artifact:build-logstash-core` to build LS gems
# You can add a version qualifier (e.g. alpha1) via the VERSION_QUALIFIER env var, e.g.
# VERSION_QUALIFIER=beta2 RELEASE=1 rake artifact:build-logstash-core
# `require 'logstash-core/version'` is aware of this env var

lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)

project_versions_yaml_path = File.expand_path("../versions.yml", File.dirname(__FILE__))
if File.exist?(project_versions_yaml_path)
  # we need to copy the project level versions.yml into the gem root
  # to be able to package it into the gems file structure
  # as the require 'logstash-core/version' loads the yaml file from within the gem root.
  #
  # we ignore the copy in git and we overwrite an existing file
  # each time we build the logstash-core gem
  original_lines = IO.readlines(project_versions_yaml_path)
  original_lines << ""
  original_lines << "# This is a copy the project level versions.yml into this gem's root and it is created when the gemspec is evaluated."
  gem_versions_yaml_path = File.expand_path("./versions-gem-copy.yml", File.dirname(__FILE__))
  File.open(gem_versions_yaml_path, 'w') do |new_file|
    # create or overwrite
    new_file.puts(original_lines)
  end
end

require 'logstash-core/version'

Gem::Specification.new do |gem|
  gem.authors       = ["Elastic"]
  gem.email         = ["info@elastic.co"]
  gem.description   = %q{The core components of logstash, the scalable log and event management tool}
  gem.summary       = %q{logstash-core - The core components of logstash}
  gem.homepage      = "http://www.elastic.co/guide/en/logstash/current/index.html"
  gem.license       = "Apache-2.0"

  gem.files         = Dir.glob(
    %w(versions-gem-copy.yml logstash-core.gemspec gemspec_jars.rb lib/**/*.rb spec/**/*.rb locales/*
    lib/logstash/api/init.ru lib/logstash-core/logstash-core.jar)
  )
  gem.test_files    = gem.files.grep(%r{^(test|spec|features)/})
  gem.name          = "logstash-core"
  gem.require_paths = ["lib"]
  gem.version       = LOGSTASH_CORE_VERSION.gsub("-", ".")

  gem.platform = "java"

  gem.add_runtime_dependency "pry", "~> 0.12"  #(Ruby license)
  gem.add_runtime_dependency "stud", "~> 0.0.19" #(Apache 2.0 license)
  gem.add_runtime_dependency "clamp", "~> 1" #(MIT license) for command line args/flags
  gem.add_runtime_dependency "filesize", "~> 0.2" #(MIT license) for :bytes config validator
  gem.add_runtime_dependency "gems", "~> 1"  #(MIT license)
  gem.add_runtime_dependency "concurrent-ruby", "~> 1", "< 1.1.10" # pinned until https://github.com/elastic/logstash/issues/13956
  gem.add_runtime_dependency "rack", '~> 2'
  gem.add_runtime_dependency "mustermann", '~> 1.0.3'
  gem.add_runtime_dependency "sinatra", '~> 2'
  gem.add_runtime_dependency 'puma', '~> 5', '>= 5.6.8'
  gem.add_runtime_dependency "jruby-openssl", "~> 0.11"
  gem.add_runtime_dependency "chronic_duration", "~> 0.10"
  gem.add_runtime_dependency "jar-dependencies",'= 0.4.1' # Pin to `0.4.1` until https://github.com/jruby/jruby/issues/7262 is resolved
  
  gem.add_runtime_dependency "treetop", "~> 1" #(MIT license)

  gem.add_runtime_dependency "i18n", "~> 1" #(MIT license)

  # filetools and rakelib
  gem.add_runtime_dependency "minitar", "~> 0.8"
  gem.add_runtime_dependency "rubyzip", "~> 1"
  gem.add_runtime_dependency "thread_safe", "~> 0.3.6" #(Apache 2.0 license)

  gem.add_runtime_dependency "jrjackson", "= #{ALL_VERSIONS.fetch('jrjackson')}" #(Apache 2.0 license)

  gem.add_runtime_dependency "elasticsearch", '~> 7'
  gem.add_runtime_dependency "manticore", '~> 0.6'

  # xpack geoip database service
  gem.add_development_dependency 'logstash-filter-geoip', '>= 7.2.1' # breaking change of DatabaseManager
  gem.add_dependency 'down', '~> 5.2.0' #(MIT license)
  gem.add_dependency 'tzinfo-data' #(MIT license)
  # TEMPORARY: Modern Rufus Scheduler 3.x subtly breaks thread joining, which
  # is done in several plugins to handle shutdowns.
  # Pin pending migration to shared Scheduler Mixin that can mitigate this issue.
  # https://github.com/logstash-plugins/logstash-mixin-scheduler/pull/1
  gem.add_runtime_dependency 'rufus-scheduler', '~> 3.0.9' #(MIT license)

  # TEMPORARY: racc-1.6.0 doesn't have JAVA counterpart (yet)
  # SEE: https://github.com/ruby/racc/issues/172
  gem.add_runtime_dependency "racc", "~> 1.5.2" #(Ruby license)
end
