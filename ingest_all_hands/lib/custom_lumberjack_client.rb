# encoding: utf-8

require "socket"
require "thread"
require "zlib"
require "json"
require "openssl"

module Lumberjack
  SEQUENCE_MAX = (2**32-1).freeze

  class CustomClient
    def initialize(opt = {})
      @host = opt[:host] || "127.0.0.1"
      @port = opt[:port] || 3333
      @client_cert = opt[:cert] if opt[:cert]
      @client_key = opt[:key] if opt[:key]
      @tls_enabled = opt.include?(:cert) && opt.include?(:cert)
      if opt.include?(:compress)
        @compress = opt[:compress]
      else
        @compress = true
      end
      @sequence = 0
      @socket = connect
    end

    private
    def connect
      socket = TCPSocket.new(@host, @port)
      return socket unless @tls_enabled

      ctx = OpenSSL::SSL::SSLContext.new
      ctx.cert = OpenSSL::X509::Certificate.new(File.read(@client_cert))
      ctx.key = OpenSSL::PKey::RSA.new(File.read(@client_key))
      ctx.ssl_version = :TLSv1_2
      # Wrap the socket with SSL/TLS
      ssl_socket = OpenSSL::SSL::SSLSocket.new(socket, ctx)
      ssl_socket.sync_close = true
      ssl_socket.connect
      ssl_socket
    end

    public
    def write(elements)
      elements = [elements] if elements.is_a?(Hash)
      send_window_size(elements.size)

      payload = elements.map { |element| JsonEncoder.to_frame(element, inc) }.join
      if @compress
        payload_to_send = compress_payload(payload)
      else
        payload_to_send = payload
      end
      send_payload(payload_to_send)
    end

    public
    def ack
      ack = @socket.sysread(6)
      if ack.size > 2
        # ACK os size 2 are "2A" messages which are keep alive
        unpacked = ack.unpack('AAN')
        if unpacked[0] == "2" && unpacked[1] == "A"
          sequence_num = unpacked[2]
          #puts "Received ACK #{sequence_num}"
        end
      end
    end

    private
    def inc
      @sequence = 0 if @sequence + 1 > Lumberjack::SEQUENCE_MAX
      @sequence = @sequence + 1
    end

    private
    def send_window_size(size)
      @socket.syswrite(["2", "W", size].pack("AAN"))
    end

    private
    def compress_payload(payload)
      compress = Zlib::Deflate.deflate(payload)
      ["1", "C", compress.bytesize, compress].pack("AANA*")
    end

    private
    def send_payload(payload)
      payload_size = payload.size
      written = 0
      while written < payload_size
        written += @socket.syswrite(payload[written..-1])
      end
    end

    public
    def send_raw(payload)
      send_payload(payload)
    end

    public
    def close
      @socket.close
    end
  end

  module JsonEncoder
    def self.to_frame(hash, sequence)
      json = hash.to_json
      json_length = json.bytesize
      pack = "AANNA#{json_length}"
      frame = ["2", "J", sequence, json_length, json]
      frame.pack(pack)
    end
  end

end