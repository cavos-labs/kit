Pod::Spec.new do |s|
  s.name           = 'CavosKit'
  s.version        = '0.1.0'
  s.summary        = 'Native P-256 keys and passkeys for @cavos/kit'
  s.description    = 'Secure Enclave backed device signers and React Native bindings for Cavos.'
  s.author         = 'Cavos'
  s.homepage       = 'https://cavos.xyz'
  s.license        = 'MIT'
  s.platforms      = { :ios => '16.0' }
  s.source         = { :git => 'https://github.com/cavos/kit.git', :tag => s.version.to_s }
  s.static_framework = true
  s.swift_version  = '5.9'
  s.source_files   = 'ios/*.{h,m,mm,swift}'
  s.frameworks     = 'Security', 'AuthenticationServices', 'CryptoKit'
  s.dependency 'ExpoModulesCore'
end
