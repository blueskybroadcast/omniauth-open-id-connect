# coding: utf-8
lib = File.expand_path('../lib', __FILE__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require 'omniauth-open-id-connect/version'

Gem::Specification.new do |spec|
  spec.name          = 'omniauth-open-id-connect'
  spec.version       = Omniauth::OpenIdConnect::VERSION
  spec.authors       = ['Bohdan Cherevatenko']
  spec.email         = ['bohdan@rubygarage.org']
  spec.summary       = %q{OpenID Connect SSO}
  spec.description   = %q{OpenID Connect SSO}
  spec.homepage      = ""
  spec.license       = "MIT"

  spec.files         = `git ls-files -z`.split("\x0")
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.test_files    = spec.files.grep(%r{^(test|spec|features)/})
  spec.require_paths = ['lib']

  spec.add_dependency 'builder'
  spec.add_dependency 'omniauth', '~> 1.0'
  spec.add_dependency 'omniauth-oauth2', '~> 1.0'
  spec.add_dependency 'rest-client'

  spec.add_development_dependency 'bundler'
  spec.add_development_dependency 'rake'
end
