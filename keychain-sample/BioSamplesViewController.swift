//
//  BioSamplesViewController.swift
//  keychain-sample
//
//  Created by Alexei Gridnev on 4/5/19.
//  Copyright © 2019 Alexei Gridnev. All rights reserved.
//

import UIKit
import LocalAuthentication

class BioSamplesViewController: UIViewController {
    
    enum BiometryState: CustomStringConvertible {
        case available, locked, notAvailable
        
        var description: String {
            switch self {
            case .available:
                return "available"
            case .locked:
                return "locked (temporarily)"
            case .notAvailable:
                return "notAvailable (turned off/not enrolled)"
            }
        }
    }

    let entryName = "keychain-sample.test_entry_bio"
    let entryContents = "Hello!"
    
    @IBOutlet weak var biometryStateLabel: UILabel!
    @IBOutlet weak var statusLabel: UILabel!
    
    private var biometryState: BiometryState {
        let authContext = LAContext()
        var error: NSError?
        
        let biometryAvailable = authContext.canEvaluatePolicy(
            LAPolicy.deviceOwnerAuthenticationWithBiometrics, error: &error)
        if let laError = error as? LAError, laError.code == LAError.Code.biometryLockout {
            return .locked
        }
        return biometryAvailable ? .available : .notAvailable
    }


    override func viewDidLoad() {
        super.viewDidLoad()
        showBiometryState()
        showStatus("---")
    }
    
    @IBAction func onCreateEntryClick(_ sender: Any) {
        let r = KeychainHelper.createBioProtectedEntry(key: entryName, data: Data(entryContents.utf8))
        showStatus(r == noErr ? "Entry created" : "Entry creation failed, osstatus=\(r)")
    }
    
    @IBAction func onReadBasicClick(_ sender: Any) {
        checkBiometryState { success in
            guard success else {
                // Biometric authentication is not available
                return
            }
            DispatchQueue.global().async {
                var result = ""
                if let data = KeychainHelper.loadBioProtected(key: self.entryName,
                                                              prompt: "Access sample keychain entry") {
                    let dataStr = String(decoding: data, as: UTF8.self)
                    result = "Keychain entry contains: \(dataStr)"
                } else {
                    result = "Couldn't read entry"
                }
                DispatchQueue.main.async {
                    self.showStatus(result)
                }
            }
        }
    }
    
    @IBAction func onReadContextClick(_ sender: Any) {
        checkBiometryState { success in
            guard success else {
                return
            }
            let authContext = LAContext()
            let accessControl = KeychainHelper.getBioSecAccessControl()
            authContext.evaluateAccessControl(accessControl,
                                              operation: .useItem,
                                              localizedReason: "Access sample keychain entry") {
                (success, error) in
                var result = ""
                if success, let data = KeychainHelper.loadBioProtected(key: self.entryName,
                                                                       context: authContext) {
                    let dataStr = String(decoding: data, as: UTF8.self)
                    result = "Keychain entry contains: \(dataStr)"
                } else {
                    result = "Can't read entry, error: \(error?.localizedDescription ?? "-")"
                }
                DispatchQueue.main.async {
                    self.showStatus(result)
                }
            }
        }
    }
    
    private func checkBiometryState(_ completion: @escaping (Bool)->Void) {
        showBiometryState()
        let bioState = self.biometryState
        guard bioState != .notAvailable else {
            showStatus("Can't read entry, biometry not available")
            completion(false)
            return
        }
        if bioState == .locked {
            // To unlock biometric authentication iOS requires user to enter a valid passcode
            let authContext = LAContext()
            authContext.evaluatePolicy(LAPolicy.deviceOwnerAuthentication,
                                       localizedReason: "Access sample keychain entry",
                                       reply: { (success, error) in
                DispatchQueue.main.async {
                    if success {
                        completion(true)
                    } else {
                        self.showStatus("Can't read entry, error: \(error?.localizedDescription ?? "-")")
                        completion(false)
                    }
                }
            })
        } else {
            completion(true)
        }
    }
    
    @IBAction func onRemoveEntryClick(_ sender: Any) {
        KeychainHelper.remove(key: entryName)
        showStatus("Entry was removed")
    }
    
    @IBAction func onCheckEntryClick(_ sender: Any) {
        let entryExists = KeychainHelper.available(key: entryName)
        showStatus(entryExists ? "Entry exists" : "Entry doesn't exist")
    }
    
    private func showBiometryState() {
        biometryStateLabel.text = "Biometry state: " + biometryState.description
    }
    
    private func showStatus(_ text: String?) {
        statusLabel.setTextWithAlphaAnimation(text)
    }
}
