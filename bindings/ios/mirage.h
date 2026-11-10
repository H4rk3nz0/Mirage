// Mirage mobile FFI — C ABI for iOS (and other C hosts).
//
// Matches the exported symbols in crates/mobile-ffi/src/cabi.rs. Kept
// hand-written (the surface is tiny and stable); if it grows, generate it with
// cbindgen instead. Include this in the bridging header of the Swift
// NEPacketTunnelProvider target (see bindings/ios/PacketTunnelProvider.swift).

#ifndef MIRAGE_H
#define MIRAGE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Opaque handle to a running tunnel. Created by a start function, freed by
// mirage_vpn_stop.
typedef struct MirageVpn MirageVpn;

// Called with each IP packet the tunnel produces for delivery to apps. Write it
// via packetFlow.writePackets. `packet` is valid only for the duration of the
// call; copy it if you retain it. `ctx` is the pointer you passed to
// mirage_vpn_start_packet_flow.
typedef void (*MirageWritePacket)(void *ctx, const uint8_t *packet, size_t len);

// Start the tunnel in packet-flow mode (the NEPacketTunnelProvider model).
// `config_json` is a NUL-terminated UTF-8 string (the desktop client's JSON
// schema). `mtu` of 0 uses the config default. Returns NULL on failure.
MirageVpn *mirage_vpn_start_packet_flow(const char *config_json,
                                        size_t mtu,
                                        MirageWritePacket write_cb,
                                        void *write_ctx);

// Start the tunnel on an existing TUN file descriptor (for hosts that have one;
// most iOS apps use the packet-flow entry above). Returns NULL on failure.
MirageVpn *mirage_vpn_start_fd(const char *config_json, int tun_fd);

// Push one app-outbound IP packet (from packetFlow.readPackets) into the tunnel.
// The bytes are copied; you keep ownership. Returns true if accepted.
bool mirage_vpn_push_packet(const MirageVpn *handle, const uint8_t *packet, size_t len);

// Stop the tunnel and free the handle. NULL is a no-op. Do not use `handle`
// after this call.
void mirage_vpn_stop(MirageVpn *handle);

// FFI version string (static; do not free).
const char *mirage_vpn_version(void);

#ifdef __cplusplus
}
#endif

#endif // MIRAGE_H
