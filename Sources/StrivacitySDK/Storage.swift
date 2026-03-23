import AppAuth
import os

/// If you implement this interface you can store the auth state as you wish.
public protocol Storage {
    /// This method is called when performing logout calls a full reset.
    func clear()

    /// It is called every time when the state is updated.
    ///
    /// - Parameters:
    ///     - authState: The auth state that should be stored
    func setState(authState: OIDAuthState?)

    /// Returns the auth state from the storage.
    ///
    /// - Returns: The state from the storage
    func getState() -> OIDAuthState?
}

struct StorageImpl: Storage {
    private let KEY = "com.strivacity.sdk.AuthState"

    private let keychain: KeychainHelper

    init(keychain: KeychainHelper = KeychainHelper()) {
        self.keychain = keychain
    }

    func clear() {
        log("clear storage")

        let query = [
            kSecAttrAccount: KEY,
            kSecClass: kSecClassGenericPassword,
        ] as [CFString: Any] as CFDictionary

        keychain.delete(query)
    }

    func setState(authState: OIDAuthState?) {
        log("save state in storage")
        if let authState = authState {
            log("authState is not nil")

            guard let data = try? NSKeyedArchiver.archivedData(withRootObject: authState, requiringSecureCoding: true) else {
                log("Error during archiving authState")
                return
            }

            let query = [
                kSecValueData: data,
                kSecClass: kSecClassGenericPassword,
                kSecAttrAccount: KEY,
            ] as [CFString: Any] as CFDictionary

            let status = keychain.set(query)

            if status != errSecSuccess {
                if status == errSecDuplicateItem {
                    let updateQuery = [
                        kSecAttrAccount: KEY,
                        kSecClass: kSecClassGenericPassword,
                    ] as [CFString: Any] as [CFString: Any] as CFDictionary

                    let attributeToUpdate = [kSecValueData: data] as CFDictionary

                    keychain.update(updateQuery, update: attributeToUpdate)
                } else {
                    log("error during saving authState, status: %{s}@", info: "\(status)")
                }
            }
        } else {
            log("authState is nil")
            clear()
        }
    }

    func getState() -> OIDAuthState? {
        log("get state from storage")

        let query = [
            kSecAttrAccount: KEY,
            kSecClass: kSecClassGenericPassword,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ] as [CFString: Any] as CFDictionary

        let result = keychain.get(query)

        guard let result = result as? Data else {
            return nil
        }

        return try? NSKeyedUnarchiver.unarchivedObject(ofClass: OIDAuthState.self, from: result)
    }

    private func log(_ msg: StaticString) {
        os_log(msg, log: OSLog(subsystem: "com.strivacity.sdk", category: "sdk-debug"), type: .info)
    }

    private func log(_ msg: StaticString, info: String) {
        os_log(msg, log: OSLog(subsystem: "com.strivacity.sdk", category: "sdk-debug"), type: .info, info)
    }
}

class KeychainHelper {
    func set(_ query: CFDictionary) -> OSStatus {
        SecItemAdd(query, nil)
    }

    func update(_ query: CFDictionary, update: CFDictionary) {
        SecItemUpdate(query, update)
    }

    func delete(_ query: CFDictionary) {
        SecItemDelete(query)
    }

    func get(_ query: CFDictionary) -> AnyObject? {
        var result: AnyObject?
        SecItemCopyMatching(query, &result)
        return result
    }
}
