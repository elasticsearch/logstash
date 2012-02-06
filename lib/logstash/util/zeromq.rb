require 'ffi-rzmq'
require "logstash/namespace"

module LogStash::Util::ZeroMQ
  CONTEXT = ZMQ::Context.new
  # LOGSTASH-400
  # see https://github.com/chuckremes/ffi-rzmq/blob/master/lib/ffi-rzmq/socket.rb#L93-117
  STRING_OPTS = %w{IDENTITY SUBSCRIBE UNSUBSCRIBE}

  def context
    CONTEXT
  end

  def setup_socket(socket, address)
    if server?
      error_check(socket.bind(address), "binding to #{address}")
    else
      error_check(socket.connect(address), "connecting to #{address}")
    end
    @logger.info("0mq: #{server? ? 'connected' : 'bound'}", :address => address)
  end

  def setup
    @zsocket = context.socket(@zmq_const)

    error_check(@zsocket.setsockopt(ZMQ::LINGER, 1),
                "while setting ZMQ::LINGER == 1)")

    # TODO (lusis)
    # wireup sockopt hash
    if @sockopt
      @sockopt.each do |opt,value|
        sockopt = opt.split('::')[1]
        option = ZMQ.const_defined?(sockopt) ? ZMQ.const_get(sockopt) : ZMQ.const_missing(sockopt)
        error_check(@zsocket.setsockopt(option, value),
                "while setting #{opt} == 1)")
      end
    end
    
    @address.each do |addr|
      setup_socket(@zsocket, addr)
    end
  end

  def error_check(rc, doing)
    unless ZMQ::Util.resultcode_ok?(rc)
      @logger.error("ZeroMQ error while #{doing}", { :error_code => rc })
      raise "ZeroMQ Error while #{doing}"
    end
  end # def error_check

  def setopts(socket, options)
    options.each do |opt,value|
      sockopt = opt.split('::')[1]
      option = ZMQ.const_defined?(sockopt) ? ZMQ.const_get(sockopt) : ZMQ.const_missing(sockopt)
      unless STRING_OPTS.include?(sockopt)
        begin
          Float(value)
          value = value.to_i
        rescue ArgumentError
          raise "#{sockopt} requires a numeric value. #{value} is not numeric"
        end
      end # end unless
      error_check(socket.setsockopt(option, value),
              "while setting #{opt} == #{value}")
    end # end each
  end # end setopts

  def reload
    error_check(@zsocket.close, "while closing socket")
    setup
  end

end # module LogStash::Util::ZeroMQ
