import AppAuth
import os

class AuthStateManager: NSObject, OIDAuthStateChangeDelegate {
    private let storage: Storage

    private var currentState: OIDAuthState? = nil
    
    private let queue = DispatchQueue(label: "com.strivacity.sdk.auth-state-manager", attributes: .concurrent)

    public init(storage: Storage) {
        self.storage = storage
    }

    func getCurrentState() -> OIDAuthState? {
        queue.sync {
            log("get current state")
            if currentState == nil {
                currentState = storage.getState()
            }
            currentState?.stateChangeDelegate = self
            return currentState
        }
    }

    func setCurrentState(state: OIDAuthState?) {
        queue.sync(flags: .barrier) {
            self.log("set current state")
            self.storage.setState(authState: state)
            self.currentState = state
            self.currentState?.stateChangeDelegate = self
        }
    }

    func resetCurrentState() {
        queue.sync(flags: .barrier) {
            self.log("reset current state")
            self.storage.clear()
            self.currentState = nil
        }
    }

    private func log(_ msg: StaticString) {
        os_log(msg, log: OSLog(subsystem: "com.strivacity.sdk", category: "sdk-debug"), type: .info)
    }

    func didChange(_ state: OIDAuthState) {
        log("state is changed, store it")
        setCurrentState(state: state)
    }
}
