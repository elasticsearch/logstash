require 'logstash/namespace'
require 'logstash/util/amqp/driver'
require 'hot_bunnies'

class LogStash::Rabbitmq::JavaDriver < LogStash::Rabbitmq::Driver
  def initialize(opts)
    connect opts
  end

  private
  def connect(opts)
    @connection = HotBunnies.connect opts
    @channel = @connection.create_channel
  end

  public
  def setup_input(opts)
    @channel.prefetch = opts[:prefetch_count]
    @exchange = @channel.exchange(opts[:exchange],
                                  :type => opts[:exchange_type],
                                  :durable => opts[:exchange_opts]["durable"],
                                  :auto_delete => opts[:exchange_opts]["auto_delete"])
    @queue = @channel.queue(opts[:queue],
                            :durable => opts[:queue_opts]["durable"],
                            :auto_delete => opts[:queue_opts]["auto_delete"],
                            :exclusive => opts[:queue_opts]["exclusive"])
    @queue.bind(@exchange, :routing_key => opts[:routing_key], :arguments => opts[:binding_arguments])
    @ack = opts["ack"]
  end

  def setup_output(opts)
    @exchange = @channel.exchange(opts[:exchange],
                                  :type => opts[:exchange_type],
                                  :durable => opts[:exchange_opts]["durable"],
                                  :auto_delete => opts[:exchange_opts]["auto_delete"])
  end

  def subscribe(&block)
    raise "You must call #{self}.setup_input before subscribing." if @queue.nil?
    @queue.subscribe(:ack => @ack, :block => true) do |headers, payload|
      block.call(payload)
      #headers.ack if @ack
    end
  end

  def publish(message, opts={})
    raise "You must call #{self}.setup_output before publishing." if @exchange.nil?
    @exchange.publish(message, opts)
  end

  def destroy
    @connection.close
  end
end
