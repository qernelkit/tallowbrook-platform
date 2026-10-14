import NIOCore
import NIOSSL

/// Client settings for the live-tracking stream (stream.tallowbrook.example:443, gRPC
/// over HTTP/2). The stream terminates on our own edge, so the groups are ours to choose.
public enum TrackingStreamTLS {
    public static func makeContext() throws -> NIOSSLContext {
        var configuration = TLSConfiguration.makeClientConfiguration()
        configuration.curves = [.x25519_MLKEM768, .x25519]
        configuration.applicationProtocols = ["h2"]
        return try NIOSSLContext(configuration: configuration)
    }

    public static func makeHandler(context: NIOSSLContext, host: String) throws -> NIOSSLClientHandler {
        try NIOSSLClientHandler(context: context, serverHostname: host)
    }
}
