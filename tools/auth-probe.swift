import Foundation
import LocalAuthentication
import Darwin

// Diagnostic only: no enrollment, keychain access, or security setting changes.
let context = LAContext()
context.localizedFallbackTitle = ""
var error: NSError?
let available = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
print("time=\(ISO8601DateFormatter().string(from: Date())) available=\(available) biometryType=\(context.biometryType.rawValue) error=\(String(describing: error))")
fflush(stdout)
if CommandLine.arguments.contains("--authenticate") && available {
    context.evaluatePolicy(.deviceOwnerAuthenticationWithBiometrics,
                           localizedReason: "Observe one Touch ID authentication for your sensor research") { success, error in
        print("time=\(ISO8601DateFormatter().string(from: Date())) success=\(success) error=\(String(describing: error))")
        fflush(stdout)
        exit(success ? 0 : 1)
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 90) {
        context.invalidate()
        print("Timed out after 90 seconds")
        exit(2)
    }
    RunLoop.main.run()
}
