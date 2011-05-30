require 'openssl'
require 'socket'

class Boat::Client
  Error = Class.new(StandardError)

  def initialize(username, key, host, opts = {})
    port = opts.fetch(:port, Boat::DEFAULT_PORT)
    @key = key
    @debug = opts.fetch(:debug, false)
    @chunk_size = opts.fetch(:chunk_size, 1048576)

    puts "[debug] connecting to #{host} port #{port}" if @debug
    @socket = TCPSocket.new(host, port)
    response = socket_gets.to_s
    raise Error, response unless response =~ /^220/

    puts "[debug] sending username" if @debug
    socket_puts "user #{username}"
    response = socket_gets.to_s
    raise Error, response unless response =~ /^251 HMAC-SHA256 (.+)/

    puts "[debug] sending password" if @debug
    password_hash = OpenSSL::HMAC.hexdigest(OpenSSL::Digest.new('sha256'), key, $1)
    socket_puts "pass #{password_hash}"
    response = socket_gets.to_s
    raise Error, response unless response =~ /^250/
  end

  def put(io, filename, size = nil, hash = nil)
    encoded_filename = CGI.escape(filename)
    puts "[debug] sending put command with filename #{encoded_filename}" if @debug
    socket_puts "put #{encoded_filename}"
    response = socket_gets.to_s
    raise Error, response unless response =~ /^250/
    server_salt = response.strip[4..-1]

    size ||= io.respond_to?(:stat) ? io.stat.size : io.length

    digest = OpenSSL::Digest.new('sha256')
    hash ||= if io.respond_to?(:path) && io.path
      digest.file(io.path).hexdigest
    elsif !io.respond_to?(:read)
      digest.hexdigest(io)
    else
      "-"
    end

    client_salt = [digest.digest((0..64).inject("") {|r, i| r << rand(256).chr})].pack("m").strip
    signature = OpenSSL::HMAC.hexdigest(digest, @key, "#{server_salt}#{encoded_filename}#{size}#{hash}#{client_salt}")

    puts "[debug] sending data command" if @debug
    socket_puts "data #{size} #{hash} #{client_salt} #{signature}"
    response = socket_gets.to_s

    # The server might already have the file with this hash - if so it'll return 255 at this point.
    if matches = response.strip.match(/\A255 accepted ([0-9a-f]{64})\z/i)
      confirm_hash = OpenSSL::HMAC.hexdigest(digest, @key, "#{client_salt}#{hash}")
      if matches[1] != confirm_hash
        raise Error, "Incorrect server signature; the srver may be faking that it received the upload"
      end
      return size
    end

    raise Error, response unless response =~ /^253/

    if io.respond_to?(:read)
      digest = OpenSSL::Digest.new('sha256') if hash == '-'
      written = 0
      while data = io.read(@chunk_size)
        if @debug
          print "[debug] sending data (#{written} / #{size} bytes)\r"
          STDOUT.flush
        end
        digest << data if hash == '-'
        @socket.write(data)
        written += data.length
      end
    else
      puts "[debug] sending data" if @debug
      @socket.write(io)
      digest << io
    end

    puts "[debug] data sent (#{size} bytes); waiting for response" if @debug
    response = socket_gets.to_s

    if response =~ /^254/ # we need to send the hash of the file because we didn't on the DATA line
      hash = digest.to_s
      signature = OpenSSL::HMAC.hexdigest(digest, @key, "#{server_salt}#{encoded_filename}#{size}#{hash}#{client_salt}")

      puts "[debug] sending confirm command" if @debug
      socket_puts "confirm #{hash} #{signature}\n"
      response = socket_gets.to_s
    end

    raise Error, response unless response && matches = response.strip.match(/\A255 accepted ([0-9a-f]{64})\z/i)

    confirm_hash = OpenSSL::HMAC.hexdigest(digest, @key, "#{client_salt}#{hash}")
    if matches[1] != confirm_hash
      raise Error, "Incorrect server signature; the srver may be faking that it received the upload"
    end

    size
  end

  def quit
    puts "[debug] sending quit" if @debug
    socket_puts "quit"
    response = socket_gets
    @socket.close
  end

  private
  def socket_gets
    data = @socket.gets
    puts "[debug] < #{data}" if @debug
    data
  end

  def socket_puts(data)
    result = @socket.puts(data)
    puts "[debug] > #{data}" if @debug
    result
  end
end

