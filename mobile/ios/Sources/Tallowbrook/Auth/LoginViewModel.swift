import Foundation
import Observation
import os

/// Sign-in with email and password through the identity service's authorization
/// endpoint, then a code exchange bound to this device.
@Observable
final class LoginViewModel {
    enum State: Equatable {
        case idle
        case signingIn
        case signedIn(customerName: String)
        case failed(message: String)
    }

    var email = ""
    var password = ""
    var isCreatingAccount = false
    var breachWarning: String?
    private(set) var state: State = .idle

    private let api: APIClient
    private let breachCheck: PasswordBreachCheck
    private let logger = Logger(subsystem: "example.tallowbrook.app", category: "auth")

    init(api: APIClient, breachCheck: PasswordBreachCheck) {
        self.api = api
        self.breachCheck = breachCheck
    }

    var canSubmit: Bool {
        email.contains("@") && password.count >= 10 && state != .signingIn
    }

    func passwordChanged() async {
        guard isCreatingAccount, password.count >= 10 else {
            breachWarning = nil
            return
        }
        do {
            switch try await breachCheck.check(password) {
            case .notFound:
                breachWarning = nil
            case .found(let times):
                breachWarning = "This password has appeared in \(times.formatted()) data breaches. Pick another one."
            }
        } catch {
            // The range lookup is advisory; sign-up goes ahead without it.
            logger.debug("Breach lookup unavailable: \(error.localizedDescription, privacy: .public)")
        }
    }

    func submit() async {
        guard canSubmit else { return }
        state = .signingIn
        let proof = PKCEChallenge()
        do {
            let code = try await api.authorize(email: email, password: password, codeChallenge: proof.challenge)
            let session = try await api.exchange(
                code: code,
                codeVerifier: proof.verifier,
                devicePublicKey: try DeviceBindingKey.publicKeyData()
            )
            try KeychainStore.save(Data(session.refreshToken.utf8), account: KeychainStore.Account.refreshToken)
            password = ""
            state = .signedIn(customerName: session.customerName)
            logger.info("Signed in")
        } catch APIError.unauthorized {
            state = .failed(message: "That email and password don't match an account.")
        } catch {
            logger.error("Sign-in failed: \(error.localizedDescription, privacy: .public)")
            state = .failed(message: "We couldn't sign you in. Check your connection and try again.")
        }
    }
}
