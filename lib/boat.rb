module Boat
  DEFAULT_PORT = 19184
  DEFAULT_SERVER_CONFIGURATION_FILE = "/etc/boat.conf"
  DEFAULT_CLIENT_CONFIGURATION_FILE = "#{ENV['HOME']}/.boat.yml"
  DEFAULT_STORAGE_DIRECTORY = "/var/lib/boat"
end

require 'boat/version'
require 'boat/client'
require 'boat/server'
require 'boat/put'
