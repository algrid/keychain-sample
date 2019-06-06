//
//  SecuredKeyViewController.swift
//  keychain-sample
//
//  Created by Alexei Gridnev on 4/22/19.
//  Copyright © 2019 Alexei Gridnev. All rights reserved.
//

import UIKit
import CommonCrypto

class SecuredKeyViewController: UIViewController {
    
    let clearText = "Hello"

    var keyName: String {
        return useBioSwitch.isOn ? "keychain-sample.sampleKeyBio" : "keychain-sample.sampleKey"
    }
    
    var key: SecKey?
    var cipherTextData: Data?
    var signature: Data?

    @IBOutlet weak var publicKeyLabel: UILabel!
    @IBOutlet weak var useBioSwitch: UISwitch!
    @IBOutlet weak var clearTextLabel: UILabel!
    @IBOutlet weak var cipherTextLabel: UILabel!
    @IBOutlet weak var signatureLabel: UILabel!
    @IBOutlet weak var signatureCheckLabel: UILabel!
    @IBOutlet weak var decryptedClearTextLabel: UILabel!
    
    override func viewDidLoad() {
        super.viewDidLoad()
        useBioSwitch.isOn = false
        clearTextLabel.text = "Clear Text: " + clearText
        showPublicKey()
    }
    
    private func showPublicKey() {
        guard let key = key, let publicKey = SecKeyCopyPublicKey(key) else {
            // Can't get public key
            publicKeyLabel.text = "Public Key: none"
            return
        }
        var error: Unmanaged<CFError>?
        if let keyData = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? {
            publicKeyLabel.text = "Public Key: " + keyData.toHexString()
        } else {
            publicKeyLabel.text = "Public Key: none"
        }
    }
    
    private func prepareKey() -> Bool {
        defer {
            showPublicKey()
        }
        guard key == nil else {
            return true
        }
        key = KeychainHelper.loadKey(name: keyName)
        guard key == nil else {
            return true
        }
        do {
            key = try KeychainHelper.makeAndStoreKey(name: keyName,
                                                     requiresBiometry: useBioSwitch.isOn)
            return true
        } catch let error {
            UIAlertController.showSimple(title: "Can't create key",
                                         text: error.localizedDescription, from: self)
        }
        return false
    }
    
    @IBAction func onEncryptClick(_ sender: Any) {
        guard prepareKey() else {
            return
        }
        
        guard let publicKey = SecKeyCopyPublicKey(key!) else {
            UIAlertController.showSimple(title: "Can't encrypt",
                                         text: "Can't get public key", from: self)
            return
        }
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(publicKey, .encrypt, algorithm) else {
            UIAlertController.showSimple(title: "Can't encrypt",
                                         text: "Algorith not supported", from: self)
            return
        }
        var error: Unmanaged<CFError>?
        let clearTextData = clearText.data(using: .utf8)!
        cipherTextData = SecKeyCreateEncryptedData(publicKey, algorithm,
                                                   clearTextData as CFData,
                                                   &error) as Data?
        guard cipherTextData != nil else {
            UIAlertController.showSimple(title: "Can't encrypt",
                                         text: (error!.takeRetainedValue() as Error).localizedDescription,
                                         from: self)
            return
        }
        let cipherTextHex = cipherTextData!.toHexString()
        cipherTextLabel.setTextWithAlphaAnimation("Cipher Text: " + cipherTextHex)
    }
    
    @IBAction func onDecryptClick(_ sender: Any) {
        guard prepareKey() else {
            return
        }
        guard cipherTextData != nil else {
            UIAlertController.showSimple(title: "Can't decrypt",
                                         text: "No encrypted data, tap \"Encrypt\" first",
                                         from: self)
            return
        }
        let algorithm: SecKeyAlgorithm = .eciesEncryptionCofactorVariableIVX963SHA256AESGCM
        guard SecKeyIsAlgorithmSupported(self.key!, .decrypt, algorithm) else {
            UIAlertController.showSimple(title: "Can't decrypt",
                                         text: "Algorith not supported", from: self)
            return
        }
        
        // SecKeyCreateDecryptedData call is blocking when the used key
        // is protected by biometry authentication. If that's not the case,
        // dispatching to a background thread isn't necessary.
        DispatchQueue.global().async {
            var error: Unmanaged<CFError>?
            let clearTextData = SecKeyCreateDecryptedData(self.key!,
                                                          algorithm,
                                                          self.cipherTextData! as CFData,
                                                          &error) as Data?
            DispatchQueue.main.async {
                guard clearTextData != nil else {
                    UIAlertController.showSimple(title: "Can't decrypt",
                                                 text: (error!.takeRetainedValue() as Error).localizedDescription,
                                                 from: self)
                    return
                }
                let clearText = String(decoding: clearTextData!, as: UTF8.self)
                self.decryptedClearTextLabel.setTextWithAlphaAnimation("Clear Text (decrypted): " +
                    clearText)
            }
        }
    }
    
    private func sign(algorithm: SecKeyAlgorithm, data: Data) {
        guard prepareKey() else {
            return
        }
        
        guard SecKeyIsAlgorithmSupported(key!, .sign, algorithm) else {
            UIAlertController.showSimple(title: "Can't sign",
                                         text: "Algorith not supported",
                                         from: self)
            return
        }
        
        // SecKeyCreateSignature call is blocking when the used key
        // is protected by biometry authentication. If that's not the case,
        // dispatching to a background thread isn't necessary.
        DispatchQueue.global().async {
            var error: Unmanaged<CFError>?
            let signature = SecKeyCreateSignature(self.key!, algorithm,
                                              data as CFData,
                                              &error) as Data?
            DispatchQueue.main.async {
                self.signature = signature
                guard signature != nil else {
                    UIAlertController.showSimple(title: "Can't sign",
                                                 text: (error!.takeRetainedValue() as Error).localizedDescription,
                                                 from: self)
                    return
                }
                let signatureHex = signature!.toHexString()
                self.signatureLabel.setTextWithAlphaAnimation("Signature: " + signatureHex)
            }
        }
    }
    
    @IBAction func onSignClick(_ sender: Any) {
        let clearTextData = clearText.data(using: .utf8)!
        sign(algorithm: .ecdsaSignatureMessageX962SHA256, data: clearTextData)
    }
    
    @IBAction func onSignDigestClick(_ sender: Any) {
        let clearTextData = clearText.data(using: .utf8)!
        sign(algorithm: .ecdsaSignatureDigestX962SHA256, data: sha256(data: clearTextData))
    }
    
    @IBAction func onVerifyClick(_ sender: Any) {
        guard prepareKey() else {
            return
        }
        guard signature != nil else {
            UIAlertController.showSimple(title: "Can't verify signature",
                                         text: "Calculate signature first!",
                                         from: self)
            return
        }
        guard let publicKey = SecKeyCopyPublicKey(key!) else {
            UIAlertController.showSimple(title: "Can't verify signature",
                                         text: "Can't get public key",
                                         from: self)
            return
        }
        
        let algorithm: SecKeyAlgorithm = .ecdsaSignatureMessageX962SHA256
        guard SecKeyIsAlgorithmSupported(publicKey, .verify, algorithm) else {
            UIAlertController.showSimple(title: "Can't verify signature",
                                         text: "Algorithm is not supported",
                                         from: self)
            return
        }
        let clearTextData = clearText.data(using: .utf8)!
        var error: Unmanaged<CFError>?
        guard SecKeyVerifySignature(publicKey, algorithm,
                                    clearTextData as CFData,
                                    signature! as CFData,
                                    &error) else {
            // Can't verify/wrong signature
            signatureCheckLabel.setTextWithAlphaAnimation("Signature check: Wrong!")
            return
        }
        signatureCheckLabel.setTextWithAlphaAnimation("Signature check: OK")
    }
    
    @IBAction func onBioSwitchChange(_ sender: Any) {
        key = nil
        cipherTextData = nil
        signature = nil
        showPublicKey()
        decryptedClearTextLabel.text = "Clear Text (decrypted):"
        signatureCheckLabel.text = "Signature check:"
        signatureLabel.text = "Signature:"
        cipherTextLabel.text = "Cipher Text:"
    }
    
    func sha256(data : Data) -> Data {
        var hash = [UInt8](repeating: 0,  count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0, CC_LONG(data.count), &hash)
        }
        return Data(bytes: hash)
    }
}
