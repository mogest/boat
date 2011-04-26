require 'hmac/sha2'
require 'eventmachine'
require 'syslog'
require 'digest'
require 'fileutils'

class Boat::Server
  # TODO
  ROOT_PATH = Dir.pwd

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
      send_data "220 Boat Server #{BOAT_VERSION}\n"
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
      elsif args.empty? || args.match(/[^a-z0-9_]/i)
        send_data "500 invalid username\n"
      else
        @username = args
        @salt = random_salt
        send_data "251 HMAC-SHA256 #{@salt}\n"
      end
    end

    def command_pass(args)
      if @authenticated
        send_data "500 already authenticated\n"
      elsif @username.nil? || @salt.nil?
        send_data "500 USER first\n"
      else
        user = @configuration.fetch("users", {}).fetch(@username, nil)
        expected = HMAC::SHA256.hexdigest(user["key"], @salt) if user
        if user && expected && args == expected
          send_data "250 OK\n"
          @user = user
          @authenticated = true
        else
          @username = @salt = nil
          send_data "401 invalid username or password\n"
        end
      end
    end

    def command_put(args)
      check_authenticated!

      if @user["access"] == "r"
        send_data "400 no write access\n"
      elsif @put_filename
        send_data "500 PUT already sent\n"
      elsif !args.match(/\A[a-z0-9_.%+-]+\z/i) # filenames should be urlencoded
        send_data "500 invalid filename\n"
      else
        repository_path = "#{ROOT_PATH}/repositories/#{@user["repository"]}"
        if @user.fetch("versioning", true) == false && File.exists?("#{repository_path}/current.#{args}")
          send_data "500 file already exists\n"
        else
          @put_filename = args
          send_data "250 OK\n"
        end
      end
    end

    def command_data(args)
      check_authenticated!

      if @put_filename.nil?
        send_data "500 PUT first\n"
      elsif @temporary_id
        send_data "500 DATA already sent\n"
      elsif !args.match(/\A[0-9]+\z/)
        send_data "500 invalid size\n"
      else
        size = args.to_i
        if size >= 1<<31
          send_data "500 size too large\n"
        else
          @temporary_id = "#{Time.now.to_i}.#{Process.pid}.#{@connection_id}"
          @temporary_filename = "#{ROOT_PATH}/tmp/#{@temporary_id}"
          @file_handle = File.open(@temporary_filename, "w")
          @temporary_files << @temporary_filename
          @digest = Digest::SHA256.new

          send_data "253 send #{size} bytes now\n"
          set_binary_mode size
        end
      end
    end

    def command_confirm(args)
      check_authenticated!

      if @put_file_salt.nil?
        send_data "500 DATA first\n"
      elsif args.nil? || (matches = args.match(/\A([0-9a-f]{64}) (\S+)\z/i)).nil?
        send_data "500 invalid hash\n"
      else
        received_client_hash = matches[1]
        received_salt = matches[2]

        expected_client_hash = HMAC::SHA256.hexdigest(@user["key"], "#{@put_file_salt}#{@put_file_hash}")
        if received_client_hash != expected_client_hash
          send_data "500 invalid confirmation hash\n"
          return
        end

        repository_path = "#{ROOT_PATH}/repositories/#{@user["repository"]}"
        FileUtils.mkdir_p(repository_path)
        version_filename = "#{repository_path}/#{@temporary_id}.#{@put_filename}"
        symlink_name = "#{repository_path}/current.#{@put_filename}"

        if @user.fetch("versioning", true) == false && File.exists?(symlink_name)
          send_data "500 file with same filename was uploaded before this upload completed\n"
          File.unlink(@temporary_filename)
          @temporary_files.delete(@temporary_filename)
          return
        end

        File.rename(@temporary_filename, version_filename)
        @temporary_files.delete(@temporary_filename)
        begin
          File.unlink(symlink_name) if File.symlink?(symlink_name)
        rescue Errno::ENOENT
        end
        File.symlink(version_filename, symlink_name)

        hash = HMAC::SHA256.hexdigest(@user["key"], "#{received_salt}#{@put_file_hash}")
        send_data "255 accepted #{hash}\n"

        @file_handle = @put_filename = @temporary_filename = @temporary_id = @put_file_salt = @put_file_hash = nil
      end
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

    def receive_binary_data(data)
      @file_handle.write data
      @digest << data
    end

    def receive_end_of_binary_data
      @file_handle.close
      @put_file_hash = @digest.to_s
      @put_file_salt = random_salt
      @digest = nil

      send_data "254 confirm #{@put_file_hash} #{@put_file_salt}\n"
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
      [Digest::SHA256.digest((0..64).inject("") {|r, i| r << rand(256).chr})].pack("m").strip
    end
  end


  def run
    trap('SIGINT') { exit }
    trap('SIGTERM') { exit }

    # TODO
    FileUtils.mkdir_p("#{ROOT_PATH}/tmp")

    while ARGV.first && ARGV.first[0..0] == '-' && ARGV.first.length > 1
      case opt = ARGV.shift
      when '-c'
        config_file = ARGV.shift

      else
        raise "unknown commandline option #{opt}"
      end
    end

    config_file ||= Boat::DEFAULT_SERVER_CONFIGURATION_FILE
    unless File.exists?(config_file)
      raise "configuration file #{config_file} does not exist"
    end

    @configuration = YAML.load(IO.read(config_file))
    if @configuration["users"].nil? || @configuration["users"].empty?
      raise "configuration file does not have any users defined in it"
    end

    #Syslog.open 'boat'

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
