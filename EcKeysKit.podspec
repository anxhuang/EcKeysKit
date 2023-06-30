#
# Be sure to run `pod lib lint EcKeysKit.podspec' to ensure this is a
# valid spec before submitting.
#
# Any lines starting with a # are optional, but their use is encouraged
# To learn more about a Podspec see https://guides.cocoapods.org/syntax/podspec.html
#

Pod::Spec.new do |s|
  s.name             = 'EcKeysKit'
  s.version          = '0.2.1'
  s.summary          = 'A CryptoKit alternative for handle Elliptic Curve Diffie-Hellman Key Exchange between cross-platforms like java and swift.'

  s.homepage         = 'https://github.com/anxhuang/EcKeysKit'
  
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'anxhuang' => 'anxanx@gmail.com' }
  s.source           = { :git => 'https://github.com/anxhuang/EcKeysKit.git', :tag => s.version.to_s }

  s.ios.deployment_target = '10.0'
  s.swift_versions = "4.0"

  s.source_files = 'Sources/EcKeysKit/**/*'
  
end
