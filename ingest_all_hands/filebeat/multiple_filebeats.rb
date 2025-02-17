# encoding: utf-8

require "open3"
require 'fileutils'
require 'open-uri'

def generate_sample_file(filename, size, line_length)
  file = File.open(filename, "w")
  words = %w(Lorem ipsum dolor sit amet consectetur adipiscing elit Ut ornare erat purus in condimentum quam accumsan ut 
  Maecenas et iaculis erat quis tempus odio Etiam ut malesuada est Nam tristique tincidunt dictum Morbi purus ipsum maximus ut risus eu 
  ultrices scelerisque est Ut bibendum augue ac nisl gravida pretium Quisque eu quam dignissim porttitor nunc non venenatis ipsum 
  Aenean vel lacinia arcu Etiam risus ex suscipit vel dui at pellentesque eleifend est Interdum et malesuada fames ac ante ipsum primis 
  in faucibus Etiam luctus nibh nulla Vivamus ante ex tempor eget sapien in finibus laoreet est In sagittis rhoncus aliquet 
  Praesent lobortis arcu efficitur purus viverra vitae fermentum nisi condimentum Nunc ornare eros nec augue consequat pulvinar Nunc convallis 
  malesuada ultrices Mauris mi ligula gravida eget dui id vehicula posuere purus Etiam ac tincidunt mauris Nulla semper eros nulla ac 
  viverra nulla pellentesque at Vivamus tincidunt consectetur purus Vivamus congue libero vel lobortis lacinia Donec consectetur sagittis leo sit 
  amet dapibus lorem faucibus ut Phasellus rhoncus risus vitae aliquam malesuada Fusce blandit dictum leo ut sodales Nunc fringilla lectus ut 
  feugiat vehicula Aliquam erat volutpat)
  sample_line = ""
  while (sample_line.size < line_length)
   sample_line = sample_line + words.sample
  end
  sample_line = sample_line + "\n"
  puts "dictionary size: #{words.size} sample_line size: #{sample_line.size}"

  iterations = size / sample_line.size
  (1..iterations).each { file.write(sample_line) }
  file.close
end

def generate_filebeat_config_file(sample_file)
  sample_file = Dir.pwd + "/#{sample_file}"
  config_string = <<-CONFIG
  filebeat.inputs:
  - type: filestream
    enabled: true

    # Paths that should be crawled and fetched. Glob based paths.
    paths:
      - #{sample_file}

  output.logstash:
    hosts: ["127.0.0.1:5044"]
    slow_start: true
  CONFIG
  File.write("filebeat.yml", config_string, mode: "w")
end

# return the name of the filebeat folder
def download_and_unpack_beats(version)
  os = RbConfig::CONFIG['host_os']
  arch = RbConfig::CONFIG['host_cpu']
  arch = 'aarch64' if RbConfig::CONFIG['host_cpu'] == "arm64"
  filebeat_archive = "filebeat-#{version}-#{os}-#{arch}.tar.gz"
  unless File.exists?(filebeat_archive)
    puts "Filebeat distribution not present for version: #{version}, OS: {os}, arch: #{arch}"
    open(filebeat_archive, 'wb') do |file|
      file << open("https://artifacts.elastic.co/downloads/beats/filebeat/#{filebeat_archive}").read
    end
    puts "Downloded."
  end

  filebeat_folder = "filebeat-#{version}-#{os}-#{arch}"
  unless File.exists?(filebeat_folder)
     puts "Filebeat distribution not unpacked, unpacking"
     system("tar zxf #{filebeat_archive}")
     puts "Filebeat distribution ready"
  end
  filebeat_folder
end

filebeat_folder = download_and_unpack_beats('8.8.2')
puts "Generating sample data"
generate_sample_file("input_sample.txt", 800 * 1024 * 1024, 1024)
puts "Ok."
puts "Setting up filebeat configuration file"
generate_filebeat_config_file("input_sample.txt")
puts "Ok."

beats_instances = 20
# beats_instances = 1
wait_threads = []
pwd = Dir.pwd
(1..beats_instances).each do |id|
  data_dir = pwd + "/data_#{id}"
  logs_dir = pwd + "/logs_#{id}"

  stdin, stdout, stderr, wait_thr = Open3.popen3("#{filebeat_folder}/filebeat --path.data #{data_dir} --path.logs #{logs_dir} --path.config #{pwd}")
  wait_threads << wait_thr
  puts "Started #{id} beats process"
end

sleep 2 * 60

# shutting down all beats
wait_threads.each { |wait_thr| Process.kill("KILL", wait_thr.pid) }

puts "Killed all beats processes"

puts "cleaning data and logs folders for all the beats"
(1..beats_instances).each do |id|
  FileUtils.remove_dir(pwd + "/data_#{id}")
  FileUtils.remove_dir(pwd + "/logs_#{id}")
end

puts "Done."

