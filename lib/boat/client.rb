require 'hmac/sha2'
require 'socket'

class Boat::Client
  Error = Class.new(StandardError)

  def initialize(username, key, host, opts = {})
    port = opts.fetch(:port, PORT)
    @key = key
    @debug = opts.fetch(:debug, false)
    @chunk_size = opts.fetch(:chunk_size, 1048576)

    puts "[debug] connecting to #{host} port #{port}" if @debug
    @socket = TCPSocket.new(host, port)
    response = @socket.gets
    raise Error, response unless response =~ /^220/

    puts "[debug] sending username" if @debug
    @socket.puts "user #{username}"
    response = @socket.gets
    raise Error, response unless response =~ /^251 HMAC-SHA256 (.+)/

    puts "[debug] sending password" if @debug
    password_hash = HMAC::SHA256.hexdigest(key, $1)
    @socket.puts "pass #{password_hash}"
    response = @socket.gets
    raise Error, response unless response =~ /^250/
  end

  def put(io, filename, size = nil)
    encoded_filename = CGI.escape(filename)
    puts "[debug] sending put command with filename #{encoded_filename}" if @debug
    @socket.puts "put #{encoded_filename}"
    response = @socket.gets
    raise Error, response unless response =~ /^250/

    if size.nil?
      size = io.respond_to?(:stat) ? io.stat.size : io.length
    end

    puts "[debug] sending data command" if @debug
    @socket.puts "data #{size}"
    response = @socket.gets
    raise Error, response unless response =~ /^253/

    digest = Digest::SHA256.new

    if io.respond_to?(:read)
      written = 0
      while data = io.read(@chunk_size)
        if @debug
          print "[debug] sending data (#{written} / #{size} bytes)\r"
          STDOUT.flush
        end
        digest << data
        @socket.write(data)
        written += data.length
      end
    else
      puts "[debug] sending data" if @debug
      @socket.write(io)
      digest << io
    end

    puts "[debug] data sent (#{size} bytes); waiting for response" if @debug
    response = @socket.gets
    raise Error, response unless response && matches = response.strip.match(/\A254 confirm ([0-9a-f]{64}) (\S+)\z/i)

    if matches[1] != digest.to_s
      raise Error, "Server reports file hash #{matches[1]} but we calculated hash #{digest.to_s}"
    end

    confirm_hash = HMAC::SHA256.hexdigest(@key, "#{matches[2]}#{digest.to_s}")
    confirm_salt = [Digest::SHA256.digest((0..64).inject("") {|r, i| r << rand(256).chr})].pack("m").strip
    puts "[debug] sending confirm command" if @debug
    @socket.puts "confirm #{confirm_hash} #{confirm_salt}\n"
    response = @socket.gets
    raise Error, response unless response && matches = response.strip.match(/\A255 accepted ([0-9a-f]{64})\z/i)

    confirm_hash = HMAC::SHA256.hexdigest(@key, "#{confirm_salt}#{digest.to_s}")
    if matches[1] != confirm_hash
      raise Error, "Server reports confirmation hash #{matches[1]} but we calculated hash #{confirm_hash}"
    end

    size
  end

  def quit
    puts "[debug] sending quit" if @debug
    @socket.puts "quit"
    response = @socket.gets
    @socket.close
  end
end

