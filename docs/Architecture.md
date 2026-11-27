# Architecture

## Modules

| Directory | Responsibility |
| --- | --- |
| `src/app/` | SwiftUI interface, native app window, and setup and service controls |
| `src/app-support/` | App artwork and secure SSH password helper |
| `rust/crates/cli/` | Rust entry point used by the app and the login service |
| `rust/crates/` | Core, bridge, keystore, native and service implementations |
| `src/mirroring/` | Media, keystore, launch, socket and decoder adapters |
| `src/phone/` | Bridge endpoint for AppleKeyStore and Secure Enclave operations |
| `src/tools/` | Host compatibility and capability inspection |
| `scripts/` | Setup and installation, shared setup dependencies, developer tools, build and packaging |
| `tests/` | Python regression tests and native checks |

## Runtime flow

```mermaid
flowchart TD
    A[sharingd and keystore adapter] --> B[Authenticated local broker]
    B -->|TLS-PSK / WebSocket over Wi-Fi or USB| C[Persistent bridge endpoint]
    C --> D[AppleKeyStore / Secure Enclave]
    E[Apple's iPhone Mirroring and media adapter] <-->|Rapport / AWDL| F[Target iPhone]
```

The bridge supplies selected cryptographic operations; the target supplies the
screen and receives input. Mirra adapts the macOS interfaces needed for this flow.
It does not implement a complete T2 chip or reproduce the hardware security
guarantees of a supported Mac. Apple's target pairing and authentication remain
in place.

## Broker and endpoint

`keystore.m` interposes AKS/DCRT calls. The Rust keystore crate exposes a private
Unix socket and an authenticated loopback socket, manages identity caching and
maps virtual session IDs to endpoint-owned handles. The Rust bridge crate connects
to the persistent phone service using TLS-PSK and WebSocket. SSH is used to install
or update that service. Python setup retains its own bridge client.

Keys use isolated endpoint keybags. Session IDs increase for the broker's
lifetime and are not reused for another handle. The wire adapter preserves the
device's attestation fields when adding the host platform field.

## Cleanup and recovery

`reset_owned_sessions` resets only handles recorded by the broker. Successful
resets release ownership; failed resets retain handles for cleanup. A failed
batch retires the broker's identity cache and reports unhealthy status. Later
cleanup does not reactivate that cache.

Memory-exhaustion recovery retries session creation after successful cleanup.
The shim still calls the native Mac reset operation and reports incomplete
bridge cleanup to its controller.

The Rust bridge health observer tracks the same process and socket throughout the session. A terminal
process result or repeated explicit unhealthy replies triggers recovery. Timeouts,
missing sockets and malformed observations remain unknown and are retried.

The Rust service owns broker workers and the sharingd controller. The Rust
keystore crate manages the injected sharingd process and its ownership journal.
Normal shutdown detaches a verified injected process for later adoption; process
birth identities and ownership records guard cleanup and recovery.

## Native startup and media

The Rust native and service crates manage launch support, delegated socket binds
and worker supervision. `launch.m` adds adapter settings only for the system
iPhone Mirroring app. The Rust supervisor retries failed backend workers after
verified cleanup. Python setup and installation still import shared lifecycle
helpers to inspect and migrate installed support.

`media.m` and `profile.m` implement the AWDL profile. Compatibility checks run
before hooks load. H.264 decoding uses the installed VideoToolbox implementation,
with an optional [decoder compatibility hook](Decoder.md).

## Installed service

The per-user LaunchAgent keeps support available without an open Terminal.
Installation copies a verified snapshot of code, runtime and private bridge
configuration. Updates replace that snapshot explicitly.

See [Background support](Service.md), [Native integration](Native.md) and
[Media](Media.md) for lifecycle and compatibility details.
