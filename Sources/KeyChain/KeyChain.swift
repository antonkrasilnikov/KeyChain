//
//  KeyChain.swift
//  core
//
//  Created by Антон Красильников on 19.04.2021.
//

import Foundation
import Security

open class KeyChain {
    
    private class func getKeychainQuery(service: String, account: String) -> [String: Any] {
        return [String(kSecClass) : kSecClassGenericPassword,
                String(kSecAttrService) : service,
                String(kSecAttrAccount) : account,
                String(kSecAttrAccessible) : kSecAttrAccessibleAfterFirstUnlock
        ]
    }
    
    @discardableResult open class func save(service: String, account: String, data: Any) -> Bool {
        var keychainQuery = Self.getKeychainQuery(service: service, account: account)
        SecItemDelete(keychainQuery as CFDictionary)
        
        let encodedData: Data
        
        do {
            if #available(iOS 11.0, *) {
                encodedData = try NSKeyedArchiver.archivedData(withRootObject: data, requiringSecureCoding: false)
            } else {
                encodedData = NSKeyedArchiver.archivedData(withRootObject: data)
            }
        } catch {
            return false
        }
        
        keychainQuery[String(kSecValueData)] = encodedData
        return SecItemAdd(keychainQuery as CFDictionary, nil) == errSecSuccess
    }
    
    open class func load(service: String, account: String) -> Any? {
        var keychainQuery = Self.getKeychainQuery(service: service, account: account)
        keychainQuery[String(kSecReturnData)] = kCFBooleanTrue
        keychainQuery[String(kSecMatchLimit)] = kSecMatchLimitOne
        
        var queryResult: AnyObject?
        let status = withUnsafeMutablePointer(to: &queryResult) {
          SecItemCopyMatching(keychainQuery as CFDictionary, $0)
        }
        
        if status == errSecSuccess, let encodedData = queryResult as? Data {
            return NSKeyedUnarchiver.unarchiveObject(with: encodedData)
        }
        return nil
    }
    
    @discardableResult open class func delete(service: String, account: String) -> Bool {
        let keychainQuery = Self.getKeychainQuery(service: service, account: account)
        let result = SecItemDelete(keychainQuery as CFDictionary)
        return result == errSecSuccess || result == errSecNoSuchKeychain
    }
}
