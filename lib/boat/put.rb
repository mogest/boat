require 'cgi'
require 'yaml'

class Boat::Put
  def run
    while ARGV.first && ARGV.first[0..0] == '-' && ARGV.first.length > 1
      case opt = ARGV.shift
      when '-v' then debug = true
      when '-c' then config_file = ARGV.shift
      else           raise "unknown commandline option #{opt}"
      end
    end

    filename, destination_filename = ARGV

    if filename == '-' && destination_filename.to_s.empty?
      raise "you must specify a destination_filename if you are uploading from stdin"
    end

    destination_filename ||= File.basename(filename)
    config_file ||= Boat::DEFAULT_CLIENT_CONFIGURATION_FILE

    unless File.exists?(config_file)
      raise "#{config_file} does not exist.  run boat configure"
    end

    configuration = YAML.load(IO.read(config_file))

    if filename != '-' && !File.exists?(filename)
      raise "#{filename} doesn't exist"
    end

    begin
      client = Boat::Client.new(configuration["username"], configuration["key"], configuration["host"], :debug => debug)
      if filename == '-'
        client.put(STDIN, destination_filename)
      else
        File.open(filename, "r") {|file| client.put(file, destination_filename)}
      end
      client.quit
    rescue BoatClient::Error => e
      STDERR.puts e.message
      exit(1)
    end
  end
end
