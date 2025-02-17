# encoding: utf-8

require "socket"
require "thread"
require "zlib"
require "json"
require "openssl"
require 'optparse'

require 'lumberjack/client'
require 'custom_lumberjack_client'
require 'java'

Thread.abort_on_exception = true
HOST="127.0.0.1"
PORT=3333
CLIENT_CERT="/Users/andrea/workspace/certificates/client_from_root.crt"
CLIENT_KEY="/Users/andrea/workspace/certificates/client_from_root.key.pkcs8"

MB = 1024 * 1024
KB = 1024

class Benchmark

  attr_reader :client_count

  def initialize(traffic_type = :tcp, beats_ack = true, acks_per_second = nil,
                 batch_size = 2000,
                 message_sizes = [8 * KB, 16 * KB, 64 * KB, 128 * KB, 512 * KB],
                 client_count = java.lang.Runtime.runtime.available_processors,
                 compress = true)
    @client_count = client_count
    @compress = compress
#     @total_traffic_per_connection = 1024 * MB
    # keep message size above 16k, requiring two TLS records
    @batch_size = batch_size
    @message_sizes = message_sizes
    puts "Starting with message_sizes: #{@message_sizes}"
    @traffic_type = traffic_type
    @beats_ack = beats_ack
    @acks_per_second = acks_per_second
  end

  def run
    puts "Using #{client_count} clients, starting at: #{Time.now()}"
    @message_sizes.each do |message_size|
      puts "\n\n"
      message = "a"*message_size
      test_iterations = 1
      #repetitions = @total_traffic_per_connection / message_size
      repetitions = 10000
      puts "Expected to send #{repetitions * client_count * test_iterations} total messages, repetitions #{repetitions} for client of #{message_size}KB size"
      puts "Writing approximately #{(client_count * repetitions * message.size)/1024.0/1024.0}Mib across #{@client_count} clients (message size: #{message_size} Kb)"
      puts "Testing sending #{repetitions} batches of #{@batch_size} events, each event is #{message_size} bytes, each batch is ~#{@batch_size * message_size} bytes"
      puts "Used compressed frames? #{@compress}"
      speeds = []
      test_iterations.times do
        speeds << execute_message_benchmark(message, repetitions)
      end

      puts "Terminated  at: #{Time.now()}"
      puts "Average evts(#{message_size}bytes)/sec (mean): #{speeds.sum / test_iterations} values: #{speeds}"
    end
  end

  private
  def execute_message_benchmark(message, repetitions = 10000)
    start = Time.now()
    sent_messages = java.util.concurrent.atomic.AtomicLong.new(0)

    if @traffic_type == :tcp
      tcp_traffic_load(client_count, message, repetitions, sent_messages)
    elsif @traffic_type == :beats
      beats_traffic_load(client_count, message, repetitions, sent_messages, @batch_size)
    else
      raise "Unrecognized traffic type: #{@traffic_type}"
    end

    puts "Done in #{Time.now() - start} seconds"

    sent_messages.get / (Time.now() - start)
  end

  private
  def tcp_traffic_load(client_count, message, repetitions, sent_messages)
    clients = @client_count.times.map { Lumberjack::Client.new }

    threads = client_count.times.map do |i|
      Thread.new(clients[i]) do |client|
        # keep message size above 16k, requiring two TLS records
        repetitions.times do
          client.send_raw(message)
          sent_messages.incrementAndGet
        end
        # Close is not available on jls-lumberjack
        if client.class == Lumberjack::CustomClient
          client.close
        end
      end
    end

    threads.each(&:join)
  end

  private
  def beats_traffic_load(client_count, message, repetitions, sent_messages, batch_size = 2000)
    clients = @client_count.times.map { Lumberjack::CustomClient.new({:port => PORT, :host => HOST, :compress => @compress}) }
#     clients = @client_count.times.map { Lumberjack::Client.new({:port => PORT, :addresses => [HOST], :ssl => false}) }

    # keep message size above 16k, requiring two TLS records
    data = { "message" => message }
    batch_array = batch_size.times.map { data }

    writer_threads = client_count.times.map do |i|
      Thread.new(clients[i]) do |client|
        # To avoid thundering
        sleep rand
        repetitions.times do
          client.write(batch_array) # this convert JSON to bytes
          written = client.ack
#           break if written != 0
          sent_messages.addAndGet(batch_size)
        end
        # Close is not available on jls-lumberjack
        if client.class == Lumberjack::CustomClient
          client.close
        end
      end
    end

#     if @beats_ack
#       puts "Starting ACK reading thread"
#       reader_threads = client_count.times.map do |i|
#         Thread.new(i) do |i|
#           client = clients[i]
#           exit = false
#           acks_counter = 0;
#           while (!exit)
#             if acks_counter == @acks_per_second
#               sleep 1
#               acks_counter = 0
#             end
#             begin
#               client.ack
#               acks_counter = acks_counter + 1
#             rescue
#               #puts "Closing reader thread for client #{i}"
#               exit = true
#             end
#           end
#         end
#       end
#     end

    writer_threads.each(&:join)
#     reader_threads.each(&:join) if @beats_ack
  end
end

DIMENSION_MAPPING = {"kb" => 1024, "mb" => 1024 * 1024}

# Accept a string (8Kb or similar) and return the number of bytes
def parse_size(s)
  # if it's plain number without dimension, parse directly to integer
  return s.to_i if s.match(/^\d+$/)

  # separate the dimension and value parts and apply the size calculation
  dimension = s.downcase[s.length-2..s.length]
  value = s[0..s.length-3]
  raise "Can't convert #{value} to number" unless value.match(/^\d+$/)
  raise "Unrecognized dimension: #{dimension}" unless DIMENSION_MAPPING.include?(dimension)
  value.to_i * DIMENSION_MAPPING[dimension]
end

# parse a list of sizes and return dimensions
def parse_sizes(list)
  list.map {|d| parse_size(d)}.sort
end

options = {}
option_parser = OptionParser.new do |opts|
  opts.banner = "Usage: ruby tcp_client.rb benchmark_client.rb --test=beats|tcp -ack [yes|no] --acks_per_second 1000"
  opts.on '-tKIND', '--test=KIND', 'Select to benchmark the TCP or Beats input'
  opts.on '-a', '--[no-]ack [FLAG]', TrueClass, 'In beats determine if read ACKs flow or not' do |v|
    options[:ack] = v.nil? ? true : v
  end
  opts.on("-fACKS", "--acks_per_second ACKS", Integer, "Rate ACKs per second")
  opts.on("--msg_sizes 8kb,16kb", Array, "List of message sizes, like 8Kb, 2Mb or just exact byte size like 2000 ") do |msg_sizes|
    options[:msg_sizes] = parse_sizes(msg_sizes)
  end
  opts.on("-bBATCH", "--batch_size BATCH", Integer, "Number of events per batch")
  opts.on("-cNUM_CLIENTS", "--clients NUM_CLIENTS", Integer, "Number of client to connect")
  opts.on('-z', '--[no-]zip [FLAG]', TrueClass, 'Use compressed frames or not') do |v|
    options[:compress] = v.nil? ? true : v
  end
end
option_parser.parse!(into: options)

puts "Parsed options: #{options}"

ack = options[:ack]

kind = :tcp
kind = options[:test].downcase.to_sym if options[:test]
acks_per_second = nil
acks_per_second = options[:acks_per_second] if options[:acks_per_second]

message_sizes = [8 * KB, 16 * KB, 64 * KB, 128 * KB, 512 * KB]
message_sizes = options[:msg_sizes] if options[:msg_sizes]

batch_size = 2000
batch_size = options[:batch_size] if options[:batch_size]

clients = 12
clients = options[:clients] if options[:clients]

benchmark = Benchmark.new(kind, ack, acks_per_second, batch_size, message_sizes, clients, options[:compress])
benchmark.run