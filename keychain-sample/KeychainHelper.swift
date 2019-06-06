//
//  KeychainHelper.swift
//  keychain-sample
//
//  Created by Alexei Gridnev on 3/11/19.
//  Copyright © 2019 Alexei Gridnev. All rights reserved.
//

import LocalAuthentication

class KeychainHelper {
    
    private init() {}       // pure helper, disable instantiation
    
    static func getPwSecAccessControl() -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?
        
        access = SecAccessControlCreateWithFlags(nil,  // Use the default allocator.
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .applicationPassword,
            &error)
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }
    
    static func getBioSecAccessControl() -> SecAccessControl {
        var access: SecAccessControl?
        var error: Unmanaged<CFError>?
        
        if #available(iOS 11.3, *) {
            access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .biometryCurrentSet,
                &error)
        } else {
            access = SecAccessControlCreateWithFlags(nil,
                kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                .touchIDCurrentSet,
                &error)
        }
        precondition(access != nil, "SecAccessControlCreateWithFlags failed")
        return access!
    }
    
    static func createEntry(key: String, data: Data, password: String) -> OSStatus {
        remove(key: key)
        
        let context = LAContext()
        context.setCredential(password.data(using: .utf8), type: .applicationPassword)
        
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key,
            kSecAttrAccessControl as String: getPwSecAccessControl(),
            kSecValueData as String   : data as NSData,
            kSecUseAuthenticationContext: context] as CFDictionary
        
        return SecItemAdd(query, nil)
    }
    
    static func createBioProtectedEntry(key: String, data: Data) -> OSStatus {
        remove(key: key)
        
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key,
            kSecAttrAccessControl as String: getBioSecAccessControl(),
            kSecValueData as String   : data ] as CFDictionary
        
        return SecItemAdd(query as CFDictionary, nil)
    }

    static func remove(key: String) {
        let query = [
            kSecClass as String       : kSecClassGenericPassword as String,
            kSecAttrAccount as String : key]
        
        SecItemDelete(query as CFDictionary)
    }
    
    static func loadPassProtected(key: String, context: LAContext? = nil) -> Data? {
        var query: [String: Any] = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue,
            kSecAttrAccessControl as String: getPwSecAccessControl(),
            kSecMatchLimit as String  : kSecMatchLimitOne]
        
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
            
            // Prevent system UI from automatically requesting password
            // if the password inside supplied context is wrong
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUIFail
        }
        
        var dataTypeRef: AnyObject? = nil
        
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == noErr {
            return (dataTypeRef! as! Data)
        } else {
            return nil
        }
    }
    
    static func loadBioProtected(key: String, context: LAContext? = nil,
                                 prompt: String? = nil) -> Data? {
        var query: [String: Any] = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue,
            kSecAttrAccessControl as String: getBioSecAccessControl(),
            kSecMatchLimit as String  : kSecMatchLimitOne ]
        
        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
            
            // Prevent system UI from automatically requesting Touc ID/Face ID authentication
            // just in case someone passes here an LAContext instance without
            // a prior evaluateAccessControl call
            query[kSecUseAuthenticationUI as String] = kSecUseAuthenticationUISkip
        }
        
        if let prompt = prompt {
            query[kSecUseOperationPrompt as String] = prompt
        }

        var dataTypeRef: AnyObject? = nil
        
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == noErr {
            return (dataTypeRef! as! Data)
        } else {
            return nil
        }
    }

    static func available(key: String) -> Bool {
        let query = [
            kSecClass as String       : kSecClassGenericPassword,
            kSecAttrAccount as String : key,
            kSecReturnData as String  : kCFBooleanTrue,
            kSecMatchLimit as String  : kSecMatchLimitOne,
            kSecUseAuthenticationUI as String : kSecUseAuthenticationUIFail] as CFDictionary
        
        var dataTypeRef: AnyObject? = nil
        
        let status = SecItemCopyMatching(query, &dataTypeRef)
        
        // errSecInteractionNotAllowed - for a protected item
        // errSecAuthFailed - when touch Id is locked
        return status == noErr || status == errSecInteractionNotAllowed || status == errSecAuthFailed
    }

    // MARK: Storing keys in the keychain
    
    static func makeAndStoreKey(name: String,
                                requiresBiometry: Bool = false) throws -> SecKey {
        removeKey(name: name)

        let flags: SecAccessControlCreateFlags
        if #available(iOS 11.3, *) {
            flags = requiresBiometry ?
                [.privateKeyUsage, .biometryCurrentSet] : .privateKeyUsage
        } else {
            flags = requiresBiometry ?
                [.privateKeyUsage, .touchIDCurrentSet] : .privateKeyUsage
        }
        let access =
            SecAccessControlCreateWithFlags(kCFAllocatorDefault,
                                            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
                                            flags,
                                            nil)!
        let tag = name.data(using: .utf8)!
        let attributes: [String: Any] = [
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecAttrKeySizeInBits as String     : 256,
            kSecAttrTokenID as String           : kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String : [
                kSecAttrIsPermanent as String       : true,
                kSecAttrApplicationTag as String    : tag,
                kSecAttrAccessControl as String     : access
            ]
        ]
        
        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw error!.takeRetainedValue() as Error
        }
        
        return privateKey
    }
    
    static func loadKey(name: String) -> SecKey? {
        let tag = name.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag,
            kSecAttrKeyType as String           : kSecAttrKeyTypeEC,
            kSecReturnRef as String             : true
        ]
        
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess else {
            return nil
        }
        return (item as! SecKey)
    }
    
    static func removeKey(name: String) {
        let tag = name.data(using: .utf8)!
        let query: [String: Any] = [
            kSecClass as String                 : kSecClassKey,
            kSecAttrApplicationTag as String    : tag
        ]

        SecItemDelete(query as CFDictionary)
    }

    
}
