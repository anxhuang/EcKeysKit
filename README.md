# EcKeysKit

[![CI Status](https://img.shields.io/travis/anxhuang/EcKeysKit.svg?style=flat)](https://travis-ci.org/anxhuang/EcKeysKit)
[![Version](https://img.shields.io/cocoapods/v/EcKeysKit.svg?style=flat)](https://cocoapods.org/pods/EcKeysKit)
[![License](https://img.shields.io/cocoapods/l/EcKeysKit.svg?style=flat)](https://cocoapods.org/pods/EcKeysKit)
[![Platform](https://img.shields.io/cocoapods/p/EcKeysKit.svg?style=flat)](https://cocoapods.org/pods/EcKeysKit)

A `CryptoKit` alternative for handle **Elliptic Curve Diffie–Hellman Key Exchange** between cross-platforms like **Java** and **Swift**.

## Example

To run the example project, clone the repo, and run `pod install` from the Example directory first.

## Requirements

An iOS project which minimum deployment version below **iOS 14**.  
If the iOS deployment target is aboved, you can just `import CryptoKit` and skip this repo. 

## Usage

### Swift
```swift
import EcKeysKit

let derData = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIK...")!
let derPublicKey = try! P256r1.EcPublicKey(der: derData)
let newPrivateKey = P256r1.EcPrivateKey()
let sharedSecret = try! newPrivateKey.sharedSecret(with: derPublicKey)
```
### Objective-C
```smalltalk
#import "EcKeysKit-Swift.h"

NSData *derData = [[NSData alloc] initWithBase64EncodedString: @"MFkwEwYHKoZIzj0CAQYIK..." options: NSDataBase64DecodingIgnoreUnknownCharacters];
P256r1EcPublicKey *derPublicKey = [[P256r1EcPublicKey alloc] initWithDer: derData error: nil];
P256r1EcPrivateKey *newPrivateKey = [[P256r1EcPrivateKey alloc] initWithRandom: true];
NSData *sharedSecret = [newPrivateKey sharedSecretWith: derPublicKey error: nil];
```

### Supported Curves
- **secp256r1:** `P256r1`
- **secp384r1:** `P384r1`
- **secp521r1:** `P521r1`
    > compatible with key size below 66 bytes that without leading zeros.

## Installation

### CocoaPods
EcKeysKit is available through [CocoaPods](https://cocoapods.org). To install
it, simply add the following line to your Podfile:

```ruby
pod 'EcKeysKit'
```

### Swift Package Manager
EcKeysKit is available through `Swift Package Manager`. To install
it, just search `.git` url by following steps:

- **File** > **Add Packages...** > **Search or Enter Package URL**
```
https://github.com/anxhuang/EcKeysKit.git
```

## Author

anxhuang, anxanx@gmail.com

## License

EcKeysKit is available under the MIT license. See the LICENSE file for more info.
