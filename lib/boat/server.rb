require 'openssl'
require 'eventmachine'
require 'fileutils'

class Boat::Server
  ConfigurationError = Class.new(StandardError)

  attr_reader :configuration

  module BoatServer
    include EventMachine::Protocols::LineText2
    NextCommand = Class.new(StandardError)
    @@last_connection_id = 0

    def initialize(configuration)
      @configuration = configuration
    end

    def post_init
      @@last_connection_id += 1
      @connection_id = @@last_connection_id
      @temporary_files = []
      @digest = OpenSSL::Digest::Digest.new('sha256')
      send_data "220 Boat Server #{Boat::VERSION}\n"
    end

    def receive_line(line)
      match = line.match(/\A(\S*)(.*)?/)
      command = match[1].downcase
      args = match[2].strip if match[2] && !match[2].strip.empty?

      begin
        if %w(user pass put get data confirm quit).include?(command)
          send("command_#{command}", args)
        else
          send_data "500 unknown command\n"
        end
      rescue NextCommand
      end
    end

    def command_user(args)
      if @authenticated
        send_data "500 already authenticated\n"
      elsif args.empty? || args.match(/[^a-z0-9_.]/i)
        send_data "500 invalid username\n"
      else
        @username = args
        @login_salt = random_salt
        send_data "251 HMAC-SHA256 #{@login_salt}\n"
      end
    end

    def command_pass(args)
      if @authenticated
        send_data "500 already authenticated\n"
      elsif @username.nil? || @login_salt.nil?
        send_data "500 USER first\n"
      else
        user = @configuration.fetch("users", {}).fetch(@username, nil)
        expected = OpenSSL::HMAC.hexdigest(@digest, user["key"], @login_salt) if user
        if user && expected && args == expected
          send_data "250 OK\n"
          @user = user
          @authenticated = true
        else
          @username = @login_salt = nil
          send_data "401 invalid username or password\n"
        end
      end
    end

    def command_put(args)
      check_authenticated!

      if @user["access"] == "r"
        send_data "400 no write access\n"
      elsif @put
        send_data "500 PUT already sent\n"
      elsif !args.match(/\A[a-z0-9_.%+-]+\z/i) # filenames should be urlencoded
        send_data "500 invalid filename\n"
      else
        if @user.fetch("versioning", true) == false && File.exists?("#{repository_path}/current.#{args}")
          send_data "500 file already exists\n"
        else
          @put = {:state => "PUT", :filename => args, :server_salt => random_salt}
          send_data "250 #{@put[:server_salt]}\n"
        end
      end
    end

    def command_data(args)
      check_authenticated!

      if @put.nil?
        send_data "500 PUT first\n"
      elsif @put[:state] != "PUT"
        send_data "500 DATA already sent\n"
      elsif (matches = args.match(/\A([0-9]+) ([0-9a-f]{64}|-) (\S+) ([0-9a-f]{64})\z/i)).nil?
        send_data "500 invalid DATA command line; requires size, hash, new salt and signature\n"
      else
        size = matches[1].to_i
        file_hash = matches[2].downcase
        client_salt = matches[3]
        signature = matches[4].downcase

        if size >= 1<<31
          send_data "500 size too large\n"
        elsif signature != OpenSSL::HMAC.hexdigest(@digest, @user["key"], "#{@put.fetch(:server_salt)}#{@put.fetch(:filename)}#{size}#{file_hash}#{client_salt}")
          send_data "500 signature is invalid\n"
        elsif File.exists?(current_filename = "#{repository_path}/current.#{@put.fetch(:filename)}") && OpenSSL::Digest.new('sha256').file(current_filename).to_s == file_hash
          signature = OpenSSL::HMAC.hexdigest(@digest, @user["key"], "#{client_salt}#{file_hash}")
          send_data "255 accepted #{signature}\n"
        else
          @put[:temporary_id] = "#{Time.now.to_i}.#{Process.pid}.#{@connection_id}"
          @put[:temporary_filename] = "#{@configuration["storage_path"]}/tmp/#{@put.fetch(:temporary_id)}"
          @put.merge!(
            :state => "DATA",
            :size => size,
            :hash => (file_hash unless file_hash == '-'),
            :client_salt => client_salt,
            :file_handle => File.open(@put[:temporary_filename], "w"),
            :digest => OpenSSL::Digest.new('sha256'))

          @temporary_files << @put[:temporary_filename]

          send_data "253 send #{size} bytes now\n"
          set_binary_mode size
        end
      end
    end

    def receive_binary_data(data)
      @put[:file_handle].write data
      @put[:digest] << data
    end

    def receive_end_of_binary_data
      @put[:file_handle].close

      if @put.fetch(:hash).nil?
        @put[:state] = "awaiting CONFIRM"
        send_data "254 send hash confirmation\n"
      else
        complete_put
      end
    end

    def command_confirm(args)
      if @put.nil? || @put[:state] != "awaiting CONFIRM"
        send_data "500 no need to send CONFIRM\n"
      elsif (matches = args.match(/\A([0-9a-f]{64}) ([0-9a-f]{64})\z/i)).nil?
        send_data "500 invalid CONFIRM command line; requires hash and signature\n"
      else
        file_hash = matches[1].downcase
        signature = matches[2].downcase

        if signature != OpenSSL::HMAC.hexdigest(@digest, @user["key"], "#{@put.fetch(:server_salt)}#{@put.fetch(:filename)}#{@put.fetch(:size)}#{file_hash}#{@put.fetch(:client_salt)}")
          send_data "500 signature is invalid\n"
          @put = nil
        else
          @put[:hash] = file_hash
          complete_put
        end
      end
    end

    def complete_put
      calculated_hash = @put.fetch(:digest).hexdigest

      if @put.fetch(:hash) != calculated_hash
        send_data "500 file hash does not match hash supplied by client\n"
        File.unlink(@put.fetch(:temporary_filename))
        @temporary_files.delete(@put.fetch(:temporary_filename))
        return
      end

      FileUtils.mkdir_p(repository_path)
      version_filename = "#{repository_path}/#{@put.fetch(:temporary_id)}.#{@put.fetch(:filename)}"
      symlink_name = "#{repository_path}/current.#{@put.fetch(:filename)}"

      if @user.fetch("versioning", true) == false && File.exists?(symlink_name)
        send_data "500 file with same filename was uploaded before this upload completed\n"
        File.unlink(@put.fetch(:temporary_filename))
        @temporary_files.delete(@put.fetch(:temporary_filename))
        return
      end

      File.rename(@put.fetch(:temporary_filename), version_filename)
      @temporary_files.delete(@put.fetch(:temporary_filename))
      begin
        File.unlink(symlink_name) if File.symlink?(symlink_name)
      rescue Errno::ENOENT
      end
      File.symlink(version_filename, symlink_name)

      signature = OpenSSL::HMAC.hexdigest(@digest, @user["key"], "#{@put.fetch(:client_salt)}#{@put.fetch(:hash)}")
      send_data "255 accepted #{signature}\n"
    ensure
      @put = nil
    end

    def command_get(args)
      check_authenticated!
      send_data "500 not implemented\n"
    end

    def command_quit(args)
      send_data "221 bye\n"
      close_connection_after_writing
    end

    def check_authenticated!
      unless @authenticated
        send_data "500 not authenticated\n"
        raise NextCommand
      end
    end

    def unbind
      @temporary_files.each do |filename|
        begin
          File.unlink(filename)
        rescue Errno::ENOENT
        end
      end
    end

    def random_salt
      [OpenSSL::Digest.new('sha256').digest((0..64).inject("") {|r, i| r << rand(256).chr})].pack("m").strip
    end

    def repository_path
      @user && "#{@configuration.fetch("storage_path")}/repositories/#{@user.fetch("repository")}"
    end
  end

  def load_configuration
    unless File.exists?(@config_file)
      raise "configuration file #{config_file} does not exist"
    end

    configuration = YAML.load(IO.read(@config_file))
    if configuration["users"].nil? || configuration["users"].empty?
      raise "configuration file does not have any users defined in it"
    end

    configuration["storage_path"] ||= Boat::DEFAULT_STORAGE_DIRECTORY
    FileUtils.mkdir_p("#{configuration["storage_path"]}/tmp")

    @configuration.update(configuration)
  rescue => e
    raise ConfigurationError, e.message, $@
  end

  def run
    trap('SIGINT') { exit }
    trap('SIGTERM') { exit }

    while ARGV.first && ARGV.first[0..0] == '-' && ARGV.first.length > 1
      case opt = ARGV.shift
      when '-c' then @config_file = ARGV.shift
      else           raise "unknown commandline option #{opt}"
      end
    end

    @config_file ||= Boat::DEFAULT_SERVER_CONFIGURATION_FILE
    @configuration = {}
    load_configuration

    trap('SIGHUP') do
      begin
        load_configuration
      rescue ConfigurationError => e
        STDERR.puts "Could not reload configuration file: #{e.message}"
      end
    end

    File.umask(0077)
    EventMachine.run do
      EventMachine.start_server(
        @configuration.fetch("listen_address", "localhost"),
        @configuration.fetch("listen_port", Boat::DEFAULT_PORT),
        BoatServer,
        @configuration)
    end
  end
end
