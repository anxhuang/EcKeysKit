//
//  ViewController.swift
//  EcKeysKit
//
//  Created by anxhuang on 06/29/2023.
//  Copyright (c) 2023 anxhuang. All rights reserved.
//

import UIKit
import EcKeysKit

class ViewController: UIViewController {
    
    private let msgLabel: UILabel = {
        let label = UILabel()
        label.numberOfLines = 0
        label.textAlignment = .center
        label.textColor = .black
        return label
    }()

    override func viewDidLoad() {
        super.viewDidLoad()
        
        view.backgroundColor = .white
        
        let stackView = UIStackView(arrangedSubviews: [
            makeButton(title: "Objective-C", color: .systemOrange, action: #selector(tapObjcButton)),
            makeButton(title: "P256r1", color: .systemRed, action: #selector(tapP256r1Button)),
            makeButton(title: "P384r1", color: .systemGreen, action: #selector(tapP384r1Button)),
            makeButton(title: "P521r1", color: .systemBlue, action: #selector(tapP521r1Button)),
            msgLabel
        ])
        stackView.axis = .vertical
        stackView.spacing = 20
        stackView.distribution = .fillEqually
        stackView.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stackView)
        NSLayoutConstraint.activate([
            stackView.topAnchor.constraint(equalTo: view.topAnchor, constant: 60),
            stackView.bottomAnchor.constraint(equalTo: view.bottomAnchor, constant: -60),
            stackView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stackView.leadingAnchor.constraint(equalTo: view.leadingAnchor, constant: 20)
        ])
        
    }
    
    private func makeButton(title: String, color: UIColor, action: Selector) -> UIButton {
        let button = UIButton()
        button.setTitle(title, for: .normal)
        button.setTitleColor(.white, for: .normal)
        button.backgroundColor = color
        button.layer.cornerRadius = 10
        button.addTarget(self, action: action, for: .touchUpInside)
        return button
    }
    
    @objc private func tapObjcButton() {
        let vc = ObjcViewController()
        present(vc, animated: true)
    }
    
    @objc private func tapP256r1Button() {
        let derData = Data(base64Encoded: "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEeLn0V/JKsIZtJMemzhb/KtoEfRfEAH74LQzE0w/Iju49WgEPmg5c+RQ4KXW1fzkCOXLJsRFGfhgCtBwrrvc7bw==")!
        let derPublicKey = try! P256r1.EcPublicKey(der: derData)
        let newPrivateKey = P256r1.EcPrivateKey()
        let sharedSecret = try! newPrivateKey.sharedSecret(with: derPublicKey)
        msgLabel.text = "SharedSecret:\n" + sharedSecret.base64EncodedString()
    }
    
    @objc private func tapP384r1Button() {
        let derData = Data(base64Encoded: "MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE+kE+Fh8UwNXjyEuWCZnyG18e2OUUQ29iP8o4DPhpKdk56ODEd2YW3oJDzh+nLu/IPjCsJKk9DxsRKvaSoETA3xWFwGrKbj84lAtMgb0Qh3M2Cm8NhzBd2DR6RoGzaBi5")!
        let derPublicKey = try! P384r1.EcPublicKey(der: derData)
        let newPrivateKey = P384r1.EcPrivateKey()
        let sharedSecret = try! newPrivateKey.sharedSecret(with: derPublicKey)
        msgLabel.text = "SharedSecret:\n" + sharedSecret.base64EncodedString()
    }

    @objc private func tapP521r1Button() {
        let derData = Data(base64Encoded: "MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQBK5LG03MuXoD2UY0G73opWBgpXT+18WllX+KrQMsB0wR8DW0wBX2vGu1CZ33VZEfkVY5c9lKigqrYlN39CyL8qKoBKT5JW/+LHnt8rhmYWlwaH34ZD7fVbsoCAyYn6CCmeSal6iUYBYpy0WtcA/cuWRFblhwNH7A1f/EvnpyBmMF0xK0=")!
        let derPublicKey = try! P521r1.EcPublicKey(der: derData)
        let newPrivateKey = P521r1.EcPrivateKey()
        let sharedSecret = try! newPrivateKey.sharedSecret(with: derPublicKey)
        msgLabel.text = "SharedSecret:\n" + sharedSecret.base64EncodedString()
    }

}

