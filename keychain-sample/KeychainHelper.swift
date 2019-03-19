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

}
