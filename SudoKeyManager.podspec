Pod::Spec.new do |spec|
  spec.name                  = 'SudoKeyManager'
  spec.version               = '1.1.0'
  spec.author                = { 'Sudo Platform Engineering' => 'sudoplatform-engineering@anonyome.com' }
  spec.homepage              = 'https://sudoplatform.com'
  spec.summary               = 'Key Manager SDK for the Sudo Platform by Anonyome Labs.'
  spec.license               = { :type => 'Apache License, Version 2.0', :file => 'LICENSE' }
  spec.source                = { :git => 'https://github.com/sudoplatform/sudo-key-manager-ios.git', :tag => "v#{spec.version}" }
  spec.source_files          = "SudoKeyManager/**/*.swift"
  spec.ios.deployment_target = '11.0'
  spec.requires_arc          = true
  spec.swift_version         = '5.0'
end
