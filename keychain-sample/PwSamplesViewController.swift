//
//  PwSamplesViewController.swift
//  keychain-sample
//
//  Created by Alexei Gridnev on 3/11/19.
//  Copyright © 2019 Alexei Gridnev. All rights reserved.
//

import UIKit
import LocalAuthentication

class PwSamplesViewController: UIViewController {
    
    let entryName = "test_entry_pass"
    let entryContents = "Hello!"
    let entryPassword = "qwerty"

    @IBOutlet weak var pwTextField: UITextField!
    @IBOutlet weak var statusLabel: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        showStatus("---")
    }

    @IBAction func onCreateClick(_ sender: Any) {
        let r = KeychainHelper.createEntry(key: entryName,
                                   data: Data(entryContents.utf8),
                                   password: entryPassword)
        if r == noErr {
            showStatus("Entry successfully created!")
        } else {
            showStatus("Entry creation failed, osstatus=\(r)")
        }
    }
    
    @IBAction func onAccessBasicClick(_ sender: Any) {
        DispatchQueue.global().async {
            let data = KeychainHelper.loadPassProtected(key: self.entryName)
            DispatchQueue.main.async {
                self.onEntryRead(data)
            }
        }
    }
    
    @IBAction func onAccessContextClick(_ sender: Any) {
        let context = LAContext()
        let accessControl = KeychainHelper.getPwSecAccessControl()
        context.evaluateAccessControl(accessControl, operation: .useItem, localizedReason: "Not used") { (success, error) in
            DispatchQueue.main.async {
                guard success else {
                    self.showStatus("evaluateAccessControl failed: \(error?.localizedDescription ?? "no error")")
                    return
                }
                let data = KeychainHelper.loadPassProtected(key: self.entryName, context: context)
                self.onEntryRead(data)
            }
        }
    }
    
    @IBAction func onAccessPwClick(_ sender: Any) {
        let context = LAContext()
        let password = pwTextField.text ?? ""
        context.setCredential(Data(password.utf8), type: .applicationPassword)
        let data = KeychainHelper.loadPassProtected(key: self.entryName, context: context)
        self.onEntryRead(data)
    }
    
    private func onEntryRead(_ data: Data?) {
        var result: String = ""
        if let data = data {
            let dataStr = String(decoding: data, as: UTF8.self)
            result = "Keychain entry contains: \(dataStr)"
        } else {
            result = "Failed to load keychain entry"
        }
        showStatus(result)
    }
    
    private func showStatus(_ text: String?) {
        statusLabel.text = text
        statusLabel.alpha = 0.0
        UIView.animate(withDuration: 1.0) {
            self.statusLabel.alpha = 1.0
        }
    }
}

