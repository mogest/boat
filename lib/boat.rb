module Boat
  BOAT_VERSION = "0.1"
  DEFAULT_PORT = 19184
  DEFAULT_SERVER_CONFIGURATION_FILE = "/etc/boat.conf"
  DEFAULT_CLIENT_CONFIGURATION_FILE = "#{ENV['HOME']}/.boat.yml"
end

require 'boat/client'
require 'boat/server'
require 'boat/put'
