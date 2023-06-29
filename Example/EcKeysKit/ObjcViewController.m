//
//  ObjcViewController.m
//  EcKeysKit_Example
//
//  Created by user on 2023/6/29.
//  Copyright © 2023 CocoaPods. All rights reserved.
//

#import "EcKeysKit-Swift.h"
#import "ObjcViewController.h"

@interface ObjcViewController ()

@property (nonatomic, strong) UILabel *msgLabel;

@end

@implementation ObjcViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    self.view.backgroundColor = [UIColor whiteColor];
    
    self.msgLabel = [[UILabel alloc] init];
    self.msgLabel.numberOfLines = 0;
    self.msgLabel.textAlignment = NSTextAlignmentCenter;
    self.msgLabel.textColor = [UIColor blackColor];
    
    UIStackView *stackView = [[UIStackView alloc] initWithArrangedSubviews: @[
        [self makeButtonWithTitle: @"P256r1" color: [UIColor systemRedColor] action: @selector(tapP256r1Button)],
        [self makeButtonWithTitle: @"P384r1" color: [UIColor systemGreenColor] action: @selector(tapP384r1Button)],
        [self makeButtonWithTitle: @"P521r1" color: [UIColor systemBlueColor] action: @selector(tapP521r1Button)],
        self.msgLabel
    ]];
    stackView.axis = UILayoutConstraintAxisVertical;
    stackView.spacing = 20;
    stackView.distribution = UIStackViewDistributionFillEqually;
    stackView.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview: stackView];
    [NSLayoutConstraint activateConstraints: @[
        [stackView.topAnchor constraintEqualToAnchor: self.view.topAnchor constant: 60],
        [stackView.bottomAnchor constraintEqualToAnchor: self.view.bottomAnchor constant: -60],
        [stackView.centerXAnchor constraintEqualToAnchor: self.view.centerXAnchor],
        [stackView.leadingAnchor constraintEqualToAnchor: self.view.leadingAnchor constant: 20]
    ]];
}

- (UIButton *)makeButtonWithTitle: (NSString *)title color: (UIColor *)color action: (SEL)action {
    UIButton *button = [[UIButton alloc] init];
    [button setTitle: title forState: UIControlStateNormal];
    [button setTitleColor: [UIColor whiteColor] forState: UIControlStateNormal];
    button.backgroundColor = color;
    button.layer.cornerRadius = 10;
    [button addTarget: self action: action forControlEvents: UIControlEventTouchUpInside];
    return button;
}

- (void)tapP256r1Button {
    NSData *derData = [[NSData alloc] initWithBase64EncodedString: @"MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLn0V/JKsIZtJMemzhb/KtoEfRfEAH74LQzE0w/Iju49WgEPmg5c+RQ4KXW1fzkCOXLJsRFGfhgCtBwrrvc7bw==" options: NSDataBase64DecodingIgnoreUnknownCharacters];
    P256r1EcPublicKey *derPublicKey = [[P256r1EcPublicKey alloc] initWithDer: derData error: nil];
    P256r1EcPrivateKey *newPrivateKey = [[P256r1EcPrivateKey alloc] initWithRandom: true];
    NSData *sharedSecret = [newPrivateKey sharedSecretWith: derPublicKey error: nil];
    NSString *base64SharedSecret = [sharedSecret base64EncodedStringWithOptions: 0];
    self.msgLabel.text = [NSString stringWithFormat: @"SharedSecret:\n%@", base64SharedSecret];
}

- (void)tapP384r1Button {
    NSData *derData = [[NSData alloc] initWithBase64EncodedString: @"MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+kE+Fh8UwNXjyEuWCZnyG18e2OUUQ29iP8o4DPhpKdk56ODEd2YW3oJDzh+nLu/IPjCsJKk9DxsRKvaSoETA3xWFwGrKbj84lAtMgb0Qh3M2Cm8NhzBd2DR6RoGzaBi5" options: NSDataBase64DecodingIgnoreUnknownCharacters];
    P384r1EcPublicKey *derPublicKey = [[P384r1EcPublicKey alloc] initWithDer: derData error: nil];
    P384r1EcPrivateKey *newPrivateKey = [[P384r1EcPrivateKey alloc] initWithRandom: true];
    NSData *sharedSecret = [newPrivateKey sharedSecretWith: derPublicKey error: nil];
    NSString *base64SharedSecret = [sharedSecret base64EncodedStringWithOptions: 0];
    self.msgLabel.text = [NSString stringWithFormat: @"SharedSecret:\n%@", base64SharedSecret];
}

- (void)tapP521r1Button {
    NSData *derData = [[NSData alloc] initWithBase64EncodedString: @"MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBK5LG03MuXoD2UY0G73opWBgpXT+18WllX+KrQMsB0wR8DW0wBX2vGu1CZ33VZEfkVY5c9lKigqrYlN39CyL8qKoBKT5JW/+LHnt8rhmYWlwaH34ZD7fVbsoCAyYn6CCmeSal6iUYBYpy0WtcA/cuWRFblhwNH7A1f/EvnpyBmMF0xK0=" options: NSDataBase64DecodingIgnoreUnknownCharacters];
    P521r1EcPublicKey *derPublicKey = [[P521r1EcPublicKey alloc] initWithDer: derData error: nil];
    P521r1EcPrivateKey *newPrivateKey = [[P521r1EcPrivateKey alloc] initWithRandom: true];
    NSData *sharedSecret = [newPrivateKey sharedSecretWith: derPublicKey error: nil];
    NSString *base64SharedSecret = [sharedSecret base64EncodedStringWithOptions: 0];
    self.msgLabel.text = [NSString stringWithFormat: @"SharedSecret:\n%@", base64SharedSecret];
}

@end
