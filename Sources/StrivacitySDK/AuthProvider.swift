import AppAuth
import os
import UIKit

/// Use this class to perform PKCE Authorization code flow to communicate with Strivacity.
public class AuthProvider {
    private let DEFAULT_SCOPES: Set<String> = ["openid", "offline"]

    private var issuer: URL
    private var redirectUri: URL
    private var clientId: String

    private var scopes: Set<String>?
    private var loginHint: String?
    private var acrValues: String?
    private var uiLocales: String?
    private var prompts: Set<String>?
    private var postLogoutUri: URL?
    private var audiences: Set<String>?

    private var authStateManager: AuthStateManager

    private var currentAuthorizationFlow: OIDExternalUserAgentSession?

    private init(_ issuer: URL, _ redirectUri: URL, _ clientId: String, _ storage: Storage?) {
        self.issuer = issuer
        self.redirectUri = redirectUri
        self.clientId = clientId

        authStateManager = AuthStateManager(storage: storage ?? StorageImpl())
    }

    /// This method creates an ``AuthProvider`` instance applying the given parameters.
    /// You can implement your own storage logic using ``Storage`` interface to store the auth state more securely.
    ///
    /// Default scopes: openid, offline. You can define more scopes using ``withScopes(_:)`` function.
    /// Please make sure you enabled refresh tokens in the client instance on admin console.
    ///
    /// - Parameters:
    ///     - issuer: The issuer URL
    ///     - redirectUri: Redirect URI that is registered in the client
    ///     - clientId: Client ID of the client
    ///     - storage: (Optional) Own implementation of a storage, where the auth state is stored
    ///
    /// - Returns: ``AuthProvider`` instance
    public static func create(issuer: URL, redirectUri: URL, clientId: String, storage: Storage?) -> AuthProvider {
        .init(issuer, redirectUri, clientId, storage)
    }

    /// With this method, you can add scopes to the authorization request. If you don't provide any
    /// scopes, default scopes are used. The scopes you provide are merged with the default scopes, so you
    /// don't need to define those.
    ///
    /// Default scopes: openid, offline.
    /// Please make sure you enabled refresh tokens in the client instance on admin console.
    ///
    /// - SeeAlso:
    ///   [Requesting Claims using Scope Values](https://openid.net/specs/openid-connect-core-1_0.html#ScopeClaims)
    ///
    /// - Parameters:
    ///     - scopes: Scopes you want to send
    ///
    /// - Returns: ``AuthProvider`` instance
    public func withScopes(_ scopes: Set<String>) -> AuthProvider {
        self.scopes = scopes
        return self
    }

    /// With this method, you can define the login hint.
    ///
    /// - SeeAlso:
    ///   [OpenID Connect Authorization Endpoint
    /// section](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
    ///
    /// - Parameters:
    ///     - loginHint:  Hint about the login identifier
    ///
    /// - Returns: ``AuthProvider`` instance
    public func withLoginHint(_ loginHint: String) -> AuthProvider {
        self.loginHint = loginHint
        return self
    }

    /// With this method, you can define the acr values.
    ///
    /// - SeeAlso:
    ///   [OpenID Connect Authorization Endpoint
    /// section](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
    ///
    /// - Parameters:
    ///     - acrValues:  Requested authentication context class reference values
    ///
    /// - Returns: ``AuthProvider`` instance
    public func withAcrValues(_ acrValues: String) -> AuthProvider {
        self.acrValues = acrValues
        return self
    }

    /// With this method, you can define the ui locales.
    ///
    /// - SeeAlso:
    ///   [OpenID Connect Authorization Endpoint
    /// section](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
    ///
    /// - Parameters:
    ///     - uiLocales:  End-user's preferred languages
    ///
    /// - Returns: ``AuthProvider`` instance
    public func withUiLocales(_ uiLocales: String) -> AuthProvider {
        self.uiLocales = uiLocales
        return self
    }

    /// With this method, you can add prompts.
    ///
    /// - SeeAlso:
    ///   [OpenID Connect Authorization Endpoint
    /// section](https://openid.net/specs/openid-connect-core-1_0.html#AuthorizationEndpoint)
    ///
    /// - Parameters:
    ///     - prompts: Prompts for reauthentication or consent of the End-User
    ///
    /// - Returns: ``AuthProvider`` instance
    public func withPrompts(_ prompts: Set<String>) -> AuthProvider {
        self.prompts = prompts
        return self
    }

    /// With this method, you can define the redirection URL after logout.
    ///
    /// - SeeAlso:
    ///   [Redirection to RP After
    /// Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RedirectionAfterLogout)
    ///
    /// - Parameters:
    ///     - postLogoutUri: Redirection URL after a logout
    ///
    /// - Returns: ``AuthProvider`` instance
    public func withPostLogoutUri(_ postLogoutUri: URL) -> AuthProvider {
        self.postLogoutUri = postLogoutUri
        return self
    }
    
    public func withAudiences(_ audiences: Set<String>) -> AuthProvider {
        self.audiences = audiences
        return self
    }

    /// Using this method you can perform a PKCE Authorization Code flow with token exchange.
    /// In the case of a successful login, the success callback is called returning the accessToken and claims.
    /// If there is any error, the onError callback is called. If an authenticated state is found, then it returns the
    /// accessToken and claims without opening the login page in a browser.
    ///
    /// Please make sure your client's "Token endpoint authentication method" is set to "None" on admin console!
    ///
    /// - Parameters:
    ///     - viewController: ViewController instance for the application
    ///     - success: this is called to pass access token and claims in a success result
    ///     - onError: this is called to pass error in a failure result
    public func startFlow(
        viewController: UIViewController,
        refreshTokenAdditionalParameters: [String: String] = [:],
        success: @escaping (String?, [AnyHashable: Any]?) -> Void,
        onError failure: @escaping (Error) -> Void
    ) {
        log("startFlow called")
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { configuration, error in
            self.log("discoverConfiguration finished")
            guard let config = configuration else {
                self.log("config is nil")
                if let error = error {
                    self.log("error came back")
                    failure(error)
                } else {
                    self.log("no error came back")
                    failure(CustomError.unexpected)
                }
                return
            }

            if self.authStateManager.getCurrentState()?.getConfiguration()?.issuer != config.issuer {
                self.log("config issuer mismatch, delete authState")
                self.authStateManager.resetCurrentState()
            }

            self.log("create auth request")

            var additionalParams: [String: String] = [:]
            if let loginHint = self.loginHint {
                additionalParams["login_hint"] = loginHint
            }
            if let acrValues = self.acrValues {
                additionalParams["acr_values"] = acrValues
            }
            if let uiLocales = self.uiLocales {
                additionalParams["ui_locales"] = uiLocales
            }
            if let prompts = self.prompts {
                additionalParams["prompt"] = prompts.joined(separator: " ")
            }

            if let audiences = self.audiences?.map({ aud in
                aud.trimmingCharacters(in: .whitespacesAndNewlines)
            }).filter({ aud in !aud.isEmpty }).nilIfEmpty {
                additionalParams["audience"] = audiences.joined(separator: " ")
            }

            let request = OIDAuthorizationRequest(
                configuration: config,
                clientId: self.clientId,
                scopes: Array(self.DEFAULT_SCOPES.union(self.scopes ?? Set())),
                redirectURL: self.redirectUri,
                responseType: OIDResponseTypeCode,
                additionalParameters: additionalParams
            )

            self.log("check authenticated")
            self
                .checkAuthenticated(refreshTokenAdditionalParameters: refreshTokenAdditionalParameters) { isAuthenticated in
                    self.log("check authenticated finished")
                    if isAuthenticated {
                        self.log("authenticated")
                        success(
                            self.authStateManager.getCurrentState()?.getAccessToken(),
                            self.authStateManager.getCurrentState()?.getClaims()
                        )
                    } else {
                        self.log("not authenticated")
                        if let userAgent = OIDExternalUserAgentIOS(presenting: viewController) {
                            self.log("user agent created successfully")
                            self.currentAuthorizationFlow = OIDAuthState.authState(
                                byPresenting: request,
                                externalUserAgent: userAgent
                            ) { authState, error in
                                self.log("authorization and token exchange finished")
                                guard let authState = authState else {
                                    self.log("authState is nil")
                                    if let error = error {
                                        self.log("error came back")
                                        failure(error)
                                    } else {
                                        self.log("no error came back")
                                        failure(CustomError.unexpected)
                                    }
                                    return
                                }

                                self.log("save authState")
                                self.authStateManager.setCurrentState(state: authState)
                                success(authState.getAccessToken(), authState.getClaims())
                            }
                        } else {
                            self.log("user agent not created")
                            failure(CustomError.userAgent)
                        }
                    }
                }
        }
    }

    /// Returns a valid accessToken if it is not expired, otherwise it tries to refresh it using the refresh token.
    ///
    /// - Parameters:
    ///     - success: this is called to pass access token in a success result
    ///     - onError: this is called to pass error in a failure result
    public func getAccessToken(
        refreshTokenAdditionalParameters: [String: String] = [:],
        accessToken success: @escaping (String?) -> Void,
        onError failure: @escaping (Error) -> Void
    ) {
        log("getAccessToken called")

        guard let currentState = authStateManager.getCurrentState() else {
            log("current state not found")
            failure(CustomError.stateMissing)
            return
        }

        log("current state found")

        currentState.performAction(freshTokens: { accessToken, _, error in
            self.log("performAction finished")
            if let error = error {
                self.log("error came back")
                failure(error)
                return
            }
            guard let accessToken = accessToken else {
                self.log("accessToken is nil")
                failure(CustomError.unexpected)
                return
            }

            self.log("accessToken successfully received")
            success(accessToken)
        }, additionalRefreshParameters: refreshTokenAdditionalParameters)
    }

    /// Returns claims from the last response of saved auth state.
    ///
    /// - Returns: Claims if it is presented otherwise nil
    public func getLastRetrievedClaims() -> [AnyHashable: Any]? {
        log("getLastReceivedClaims called")
        return authStateManager.getCurrentState()?.getClaims()
    }
    
    /// Revokes the active refresh token, or the access token if no refresh token is available.
    /// On success, clears the stored auth state and calls `callback` with `nil`.
    ///
    /// Calls `callback` with ``CustomError/operationNotPossible`` if there is no current state,
    /// no revocation endpoint, or no token to revoke. Calls `callback` with the underlying
    /// `Error` if the network request fails, or with ``CustomError/unexpected`` for a non-200
    /// response or an unexpected response type.
    ///
    /// - Parameters:
    ///     - callback: Called on the main thread when the operation completes. Receives `nil` on success or an error on failure.
    public func revoke(finished callback: @escaping (Error?) -> Void) {
        log("revoke called")

        guard let currentState = authStateManager.getCurrentState() else {
            log("currentState is nil")
            callback(CustomError.operationNotPossible)
            return
        }

        guard
            let revocationEndpoint = currentState.getConfiguration()?
                .revocableEndpoint
        else {
            log("revocation endpoint is nil")
            callback(CustomError.operationNotPossible)
            return
        }
        
        var tokenToRevoke: (token: String, typeHint: String)? = nil
        if let refreshToken = currentState.getRefreshToken() {
            tokenToRevoke = (token: refreshToken, typeHint: "refresh_token")
        } else if let accessToken = currentState.getAccessToken() {
            tokenToRevoke = (token: accessToken, typeHint: "access_token")
        }
        
        guard let tokenToRevoke = tokenToRevoke else {
            log("No token to revoke")
            callback(CustomError.operationNotPossible)
            return
        }
        
        var request = URLRequest(url: revocationEndpoint)
        request.httpMethod = "POST"
        request.setValue(
            "application/x-www-form-urlencoded",
            forHTTPHeaderField: "Content-Type"
        )

        var bodyComponents = URLComponents()
        bodyComponents.queryItems = [
            URLQueryItem(name: "token", value: tokenToRevoke.token),
            URLQueryItem(name: "token_type_hint", value: tokenToRevoke.typeHint),
            URLQueryItem(name: "client_id", value: clientId),
        ]

        request.httpBody = bodyComponents.query?.data(using: .utf8)

        URLSession.shared.dataTask(with: request) { data, response, error in
            DispatchQueue.main.async {
                if let error = error {
                    self.log("Revocation request failed")
                    callback(error)
                    return
                }

                guard let httpResponse = response as? HTTPURLResponse else {
                    self.log("Unexpected response")
                    callback(CustomError.unexpected)
                    return
                }

                // Revocation endpoint returns 200 on success
                if httpResponse.statusCode == 200 {
                    self.log("Token revoked successfully")
                    self.authStateManager.resetCurrentState()
                    callback(nil)
                } else {
                    self.log("Token revocation failed")
                    callback(CustomError.unexpected)
                }
            }
        }.resume()
    }

    /// This method tries to log out the authenticated account, and set the current state. If the state
    /// has no configuration, then reset the storage and call the callback with nil.
    /// A browser appears with the logout page of the Strivacity application if it successfully logged out the account.
    /// If any error happens, callback is called with the error.
    ///
    /// - Parameters:
    ///     - viewController: ViewController instance for the application
    ///     - callback: this will be called after a logout (it can be successful or not). If any error happens, the
    /// error is returned in the parameter.
    public func logout(viewController: UIViewController, finished callback: @escaping (Error?) -> Void) {
        log("logout called")
        guard let config = authStateManager.getCurrentState()?.getConfiguration() else {
            log("config is nil")
            authStateManager.resetCurrentState()
            callback(nil)
            return
        }

        if
            let idToken = authStateManager.getCurrentState()?.lastTokenResponse?.idToken,
            let defaultPostLogoutUri = URL(string: "\(issuer)/myaccount/#/logged-out") {
            log("create endsession request")
            let endSessionRequest = OIDEndSessionRequest(
                configuration: config,
                idTokenHint: idToken,
                postLogoutRedirectURL: postLogoutUri ?? defaultPostLogoutUri,
                additionalParameters: nil
            )

            if let userAgent = OIDExternalUserAgentIOS(presenting: viewController) {
                log("user agent created successfully")
                currentAuthorizationFlow =
                    OIDAuthorizationService.present(endSessionRequest, externalUserAgent: userAgent) { _, _ in
                        self.log("logged out finished")
                        self.authStateManager.resetCurrentState()
                        callback(nil)
                    }
            } else {
                log("user agent not created")
                authStateManager.resetCurrentState()
                callback(CustomError.userAgent)
            }
        } else {
            log("failed to get idToken or create default post logout url")
            authStateManager.resetCurrentState()
            callback(CustomError.stateMissing)
        }
    }

    /// With this method you can easily check if a state is authenticated or not. It also
    /// tries to refresh the access token if needed. If the state is not authenticated or
    /// it cannot refresh the access token, false returns, otherwise true.
    ///
    /// - Parameters:
    ///     - callback: this is called to pass if state is authenticated or not
    public func checkAuthenticated(
        refreshTokenAdditionalParameters: [String: String] = [:],
        isAuthenticated callback: @escaping (Bool) -> Void
    ) {
        log("checkAuthenticated called")
        guard let currentState = authStateManager.getCurrentState() else {
            log("currentState is nil")
            callback(false)
            return
        }

        log("trying to refresh token")
        currentState.performAction(freshTokens: { accessToken, _, error in
            self.log("performing action finished")

            if let accessToken = accessToken, error == nil {
                self.log("token refreshed")
                callback(true)
            } else {
                self.log("token not refreshed")
                callback(false)
            }
        }, additionalRefreshParameters: refreshTokenAdditionalParameters)
    }

    /// With this method you can get the last token response additional parameters. This can be
    /// useful if you are using token refresh hook and you would like to pass additional information
    /// back to your application.
    public func getLastTokenResponseAdditionalParameters() -> [String: Any] {
        guard let currentState = authStateManager.getCurrentState() else {
            log("currentState is nil")
            return [:]
        }
        return currentState.lastTokenResponse?.additionalParameters as? [String: Any] ?? [:]
    }

    private func log(_ msg: StaticString, type logType: OSLogType = .info) {
        os_log(msg, log: OSLog(subsystem: "com.strivacity.sdk", category: "sdk-debug"), type: logType)
    }

    /// Call this function in your AppDelegate to resume the flow after the redirection
    ///
    /// - Parameters:
    ///     - url: URL parameter of the overriden function in your AppDelegate class
    public func resumeExternalUserAgentFlow(url: URL) -> Bool {
        if let authorizationFlow = currentAuthorizationFlow, authorizationFlow.resumeExternalUserAgentFlow(with: url) {
            currentAuthorizationFlow = nil
            return true
        }
        return false
    }
}

extension OIDServiceConfiguration {
    var revocableEndpoint: URL? {
        get {
            guard
                let revocableEndpoint = self.discoveryDocument?
                    .discoveryDictionary["revocation_endpoint"] as? String
            else {
                return nil
            }
            return URL(string: revocableEndpoint)
        }
    }
}

extension OIDAuthState {
    func getClaims() -> [AnyHashable: Any]? {
        if let idToken = lastTokenResponse?.idToken {
            return OIDIDToken(idTokenString: idToken)?.claims
        }
        return nil
    }

    func getAccessToken() -> String? {
        lastTokenResponse?.accessToken
    }
    
    func getRefreshToken() -> String? {
        lastTokenResponse?.refreshToken
    }

    func getConfiguration() -> OIDServiceConfiguration? {
        lastTokenResponse?.request.configuration ?? lastAuthorizationResponse.request.configuration
    }
}

enum CustomError: Error {
    case unexpected
    case userAgent
    case stateMissing
    case appDelegate
    case operationNotPossible
}

extension CustomError: LocalizedError {
    public var errorDescription: String? {
        switch self {
        case .unexpected:
            return NSLocalizedString("Unexpected error", comment: "Custom error")
        case .userAgent:
            return NSLocalizedString("Failed to create external user agent", comment: "Custom error")
        case .stateMissing:
            return NSLocalizedString("You have to perform a login before use this", comment: "Custom error")
        case .appDelegate:
            return NSLocalizedString("Error accessing AppDelegate", comment: "Custom error")
        case .operationNotPossible:
            return NSLocalizedString("Operation cannot be performed", comment: "Custom error")
        }
    }
}

extension Array {
    var nilIfEmpty: [Element]? {
        get {
            return isEmpty ? nil : self
        }
    }
}
