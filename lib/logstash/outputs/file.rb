require "logstash/namespace"
require "logstash/outputs/base"

# File output.
#
# Write events to files on disk. You can use fields from the
# event as parts of the filename.
class LogStash::Outputs::File < LogStash::Outputs::Base

  config_name "file"
  plugin_status "unstable"

  # The path to the file to write. Event fields can be used here, 
  # like "/var/log/logstash/%{@source_host}/%{application}"
  config :path, :validate => :string, :required => true

  # The maximum size of file to write. When the file exceeds this
  # threshold, it will be rotated to the current filename + ".1"
  # If that file already exists, the previous .1 will shift to .2
  # and so forth.
  #
  # NOT YET SUPPORTED
  config :max_size, :validate => :string

  # The format to use when writing events to the file. This value
  # supports any string and can include %{name} and other dynamic
  # strings.
  #
  # If this setting is omitted, the full json representation of the
  # event will be written as a single line.
  config :message_format, :validate => :string

  # Flush interval for flushing writes to log files. 0 will flush on every meesage
  config :flush_interval, :validate => :number, :default => 2

  public
  def register
    require "fileutils" # For mkdir_p
    @files = {}
    now = Time.now
    @last_flush_cycle = now
    @last_stale_cleanup_cycle = now
    flush_interval = @flush_interval.to_f
    @stale_cleanup_interval = 10
  end # def register

  public
  def receive(event)
    return unless output?(event)

    path = event.sprintf(@path)
    fd = open(path)

    # TODO(sissel): Check if we should rotate the file.

    if @message_format
      fd.write(event.sprintf(@message_format) + "\n")
    else
      fd.write(event.to_json + "\n")
    end
    flush(fd)
    close_stale_files
  end # def receive

  def teardown
    @files.each do |fd|
      unless fd.closed?
        fd.flush
        fd.close
      end
    end
  end

  private
  def flush(fd)
    if flush_interval > 0
      flush_pending_files
    else
      fd.flush
    end
  end

  # every flush_interval seconds or so (triggered by events, but if there are no events there's no point flushing files anyway)
  def flush_pending_files
    if Time.now - @last_flush_cycle > flush_interval
      @logger.debug("Starting flush cycle")
      @files.each do |path, fd|
        @logger.debug("Flushing file", :path => path, :fd => fd)
        fd.flush
      end
      @last_flush_cycle = Time.now
    end
  end

  # every 10 seconds or so (triggered by events, but if there are no events there's no point closing files anyway)
  def close_stale_files
    now = Time.now
    if now - @last_stale_cleanup_cycle > @stale_cleanup_interval
      @logger.debug("Starting stale files cleanup cycle", :files => @files)
      inactive_files = @files.select do |path, fd|
        not fd.active
      end
      @logger.debug("%d stale files found" % inactive_files.count, :inactive_files => inactive_files)
      inactive_files.each do |path, fd|
        @logger.debug("Closing file %s" % path)
        fd.close
        @files.delete(path)
      end
      # mark all files as inactive, a call to write will mark them as active again
      @files.each do |path, fd|
        fd.active = false
      end
      @last_stale_cleanup_cycle = now
    end
  end

  def open(path)
    return @files[path] if @files.include?(path)

    @logger.info("Opening file", :path => path)

    dir = File.dirname(path)
    if !Dir.exists?(dir)
      @logger.info("Creating directory", :directory => dir)
      FileUtils.mkdir_p(dir) 
    end

    # work around a bug opening fifos (bug JRUBY-6280)
    stat = File.stat(path) rescue nil
    if stat and stat.ftype == "fifo" and RUBY_PLATFORM == "java"
      @files[path] = java.io.FileWriter.new(java.io.File.new(path))
    else
      @files[path] = File.new(path, "a")
    end
    class << @files[path]
      alias :write_real :write
      def write(str)
        write_real(str)
        @active = true
      end
      attr_accessor :active
    end
    @files[path]
  end
end # class LogStash::Outputs::File
