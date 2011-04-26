# -*- encoding: utf-8 -*-
require File.expand_path("../lib/boat/version", __FILE__)

Gem::Specification.new do |s|
  s.name        = "boat"
  s.version     = Boat::VERSION
  s.platform    = Gem::Platform::RUBY
  s.authors     = ["Roger Nesbitt"]
  s.email       = []
  s.homepage    = "http://rubygems.org/gems/boat"
  s.summary     = "File upload client and server specifically aimed at transferring already-encrypted backups"
  s.description = s.summary

  s.required_rubygems_version = ">= 1.3.6"
  s.rubyforge_project         = "boat"

  s.files        = `git ls-files`.split("\n")
  s.executables  = `git ls-files`.split("\n").map{|f| f =~ /^bin\/(.*)/ ? $1 : nil}.compact
  s.require_path = 'lib'
end
