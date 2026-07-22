// Reference iOS Packet Tunnel Provider that runs a Mirage tunnel.
//
// This is a SKELETON to build a real Network Extension on top of, not a finished
// app. It shows the full lifecycle: bridge the NEPacketTunnelFlow to the Rust
// core's packet-flow C ABI (see bindings/ios/mirage.h), start it, and pump
// packets both directions. Search for `TODO(app)` for integration points.
//
// Requirements (all gated behind a paid Apple Developer account — see
// docs/building-ios.md):
//   * A "Packet Tunnel Provider" app-extension target.
//   * The `com.apple.developer.networking.networkextension` entitlement with the
//     `packet-tunnel-provider` value, plus a matching provisioning profile.
//   * A bridging header that `#import "mirage.h"`.
//   * Link the XCFramework built from crates/mobile-ffi (see docs/building-ios.md).

import NetworkExtension

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var handle: OpaquePointer?

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        // TODO(app): load the client config JSON (same schema as the desktop
        // client) from your app group / keychain. Never hard-code secrets.
        guard let configJson = loadConfigJson() else {
            completionHandler(NSError(domain: "Mirage", code: 1))
            return
        }

        // Configure the tunnel's virtual interface. iOS routes matching packets
        // into `packetFlow`; Mirage tunnels them. A default route captures all.
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "127.0.0.1")
        settings.ipv4Settings = {
            let s = NEIPv4Settings(addresses: ["10.111.0.2"], subnetMasks: ["255.255.255.255"])
            s.includedRoutes = [NEIPv4Route.default()]
            return s
        }()
        settings.mtu = 1400
        settings.dnsSettings = NEDNSSettings(servers: ["1.1.1.1"]) // TODO(app): a DNS you trust

        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self = self, error == nil else {
                completionHandler(error)
                return
            }
            self.startCore(configJson: configJson, completionHandler: completionHandler)
        }
    }

    private func startCore(configJson: String,
                           completionHandler: @escaping (Error?) -> Void) {
        // The C write callback delivers tunnel-produced packets back to the OS.
        // We pass `self` as the opaque context so the callback can reach
        // packetFlow. `Unmanaged` keeps the pointer stable for the tunnel's life.
        let ctx = Unmanaged.passUnretained(self).toOpaque()

        let writeCallback: MirageWritePacket = { ctx, packetPtr, len in
            guard let ctx = ctx, let packetPtr = packetPtr else { return }
            let provider = Unmanaged<PacketTunnelProvider>.fromOpaque(ctx).takeUnretainedValue()
            let data = Data(bytes: packetPtr, count: len)
            provider.packetFlow.writePackets([data], withProtocols: [AF_INET as NSNumber])
        }

        handle = configJson.withCString { cfg in
            mirage_vpn_start_packet_flow(cfg, 0, writeCallback, ctx)
        }
        guard handle != nil else {
            completionHandler(NSError(domain: "Mirage", code: 2))
            return
        }

        readAppPackets()          // start pumping outbound packets into Mirage
        completionHandler(nil)    // tunnel is up
    }

    // Continuously read packets the apps are sending and push them into the core.
    private func readAppPackets() {
        packetFlow.readPackets { [weak self] packets, _ in
            guard let self = self, let handle = self.handle else { return }
            for packet in packets {
                packet.withUnsafeBytes { raw in
                    if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                        _ = mirage_vpn_push_packet(handle, base, raw.count)
                    }
                }
            }
            self.readAppPackets() // loop
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        if let handle = handle {
            mirage_vpn_stop(handle)
            self.handle = nil
        }
        completionHandler()
    }

    private func loadConfigJson() -> String? {
        // TODO(app): return your real config JSON.
        return nil
    }
}
