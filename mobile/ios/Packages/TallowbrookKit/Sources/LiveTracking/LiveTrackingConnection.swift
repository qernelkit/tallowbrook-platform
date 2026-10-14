import NIOCore
import NIOPosix
import NIOSSL

/// A position update for a parcel on a courier's van.
public struct VanPosition: Equatable, Sendable {
    public let trackingNumber: String
    public let latitude: Double
    public let longitude: Double
    public let stopsBefore: Int
}

/// Opens the live-tracking stream. The gRPC framing lives in the generated client; this
/// type only owns the event loop and the secured channel.
public final class LiveTrackingConnection: Sendable {
    public static let defaultHost = "stream.tallowbrook.example"
    public static let defaultPort = 443

    private let group: MultiThreadedEventLoopGroup
    private let host: String
    private let port: Int

    public init(host: String = LiveTrackingConnection.defaultHost, port: Int = LiveTrackingConnection.defaultPort) {
        self.group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        self.host = host
        self.port = port
    }

    public func connect() async throws -> Channel {
        let context = try TrackingStreamTLS.makeContext()
        let host = self.host
        let bootstrap = ClientBootstrap(group: group)
            .channelOption(ChannelOptions.socketOption(.so_reuseaddr), value: 1)
            .connectTimeout(.seconds(10))
            .channelInitializer { channel in
                channel.eventLoop.makeCompletedFuture {
                    let handler = try TrackingStreamTLS.makeHandler(context: context, host: host)
                    try channel.pipeline.syncOperations.addHandler(handler)
                }
            }
        return try await bootstrap.connect(host: host, port: port).get()
    }

    public func shutdown() async throws {
        try await group.shutdownGracefully()
    }
}
