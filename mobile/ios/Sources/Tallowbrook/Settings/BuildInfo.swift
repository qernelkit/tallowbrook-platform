import Foundation

/// Version details for the About screen and support requests.
struct BuildInfo {
    let version: String
    let build: String
    let commit: String

    static let current = BuildInfo(bundle: .main)

    init(bundle: Bundle) {
        version = bundle.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String ?? "0.0"
        build = bundle.object(forInfoDictionaryKey: "CFBundleVersion") as? String ?? "0"
        commit = bundle.object(forInfoDictionaryKey: "TBGitCommit") as? String ?? "unknown"
    }

    var shortSHA: String { String(commit.prefix(7)) }

    var summary: String { "\(version) (\(build), \(shortSHA))" }
}
