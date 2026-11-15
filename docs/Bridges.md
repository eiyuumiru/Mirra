# Bridge compatibility

The bridge and target are separate devices. The bridge must run **iOS 15 or
later** and have an active jailbreak to run Mirra's helper; the target follows
[Apple's iPhone Mirroring requirements](https://support.apple.com/en-us/120421).

## Requirements

- An active jailbreak, OpenSSH and permission to run the signed helper.
- `ldid` available on the SSH shell's PATH or a supported jailbreak path.
- An arm64 device running iOS 15 or later, matching the endpoint's build target.
- Available AppleKeyStore and activation APIs, a matching device certificate,
  and working attested-key operations.

The reference bridge is iPhone XS on iOS 17.2. The
[keystore symbol fallback](KeyStore.md) records @OiviaDesu's iPhone 6s Plus
results and the limits of that evidence. Other devices and jailbreaks need
setup and Mirroring validation. Symbol availability and a matching architecture
alone do not establish compatibility.

Jailbreaks may impose passcode or Secure Enclave restrictions. Review the
jailbreak's documentation before testing; for example,
[palera1n's requirements](https://github.com/palera1n/palera1n#readme).
Successful symbol lookup, SSH access or key generation does not verify every
SEP operation needed for authentication. A bridge must also complete signing,
remote-session creation and confirmation during a live Mirroring connection.
Mirra cannot repair an unavailable SEP. A11 jailbreak configurations with SEP
restrictions need separate validation; use a compatible bridge rather than
changing phone security settings as a Mirra troubleshooting step.

## Current implementation limits

These are source and protocol limits, not a list of tested phone models.
The iOS 15 minimum does not guarantee that every later iOS release can run
the helper or provide compatible private APIs.

| Boundary | Current behavior |
| --- | --- |
| Endpoint executable | Thin generic arm64 for device iOS, built with a minimum of 15.0. An arm64e physical device is a separate compatibility question; an arm64e endpoint binary is rejected |
| Required private APIs | All 18 keystore functions must resolve. Additional symbol discovery applies to iOS 15; later releases rely on exports. Resolution does not verify signatures, entitlements or SEP behavior |
| Key creation | The endpoint and Python broker accept classes 9, 10 and 11. The macOS adapter redirects parameterized creation only for classes 9 and 10; other creation calls retain Apple's native path |
| Key layout | Only the reviewed ordered DER fields are adapted to platform 3. Unknown layouts are refused; the final wire identity must fit within 65,536 bytes |
| Per-process state | At most 8 identities and 16 simultaneous native sessions. Identities are process-local; reconnecting SSH does not restore their keybags |
| Transport | JSON messages are bounded to 262,144 bytes and individual native blobs to 65,536 bytes. Calls are serialized; a timed-out stream needs a new session |
| Certificate preparation | Certificate size is limited to 1 MiB. Issuance waits up to 40 seconds after the native request returns; the remote setup command has a separate 55-second deadline |
| Readiness | Setup checks the certificate binding, a fresh class-9 attested key, local validation and wire layout. It does not exercise remote signing, the complete authentication handshake or media |

`make endpoint-protocol` exercises the production endpoint and Python broker
using synthetic native APIs on the development Mac. It covers malformed native
results, missing APIs, certificate callbacks, capacity and cleanup. Passing these
fixtures does not certify any iPhone, iOS build, jailbreak or genuine SEP session.
Private API changes and jailbreak restrictions still require device testing.

Custom endpoint imports are checked for architecture and platform, but their
minimum OS is not compared with the connected bridge before deployment. The
official compiler independently enforces the iOS 15 build target. Avoid supplying
a custom endpoint built for an OS newer than the bridge.

## USB and SSH

USB selection uses the bridge's stable identifier and supports a configurable
phone SSH port. Imported profiles can also filter by product identifier.
Wi-Fi SSH uses the verified bridge address and account. See
[Configuration](Configuration.md) for transport settings.

Each bridge must use its own certificate and attested keys. Mirra verifies the
key's wire format before publishing a ready profile. Unrecognized layouts need
review rather than field substitutions.

## Rootless layouts

Mirra searches for `ldid` on PATH and at standard rootful/rootless locations,
including `/var/jb/usr/bin/ldid` and `/usr/bin/ldid`. Rootless paths follow the
convention described in [Theos documentation](https://theos.dev/docs/rootless).

When the standard `/var/jb/usr/bin` bootstrap is present, default deployments
use `/var/jb/var/mobile/MirraCache/<deployment-id>` for the helper and certificate.
Each attempt creates a new directory. Existing deployments and custom roots
are preserved. RootHide's existing path handling is retained separately, but
RootHide remains unsupported. No existing cache directory is replaced or redirected.

This addresses the executable placement implicated by
[issue #1](https://github.com/eiyuumiru/Mirra/issues/1). Follow-up iOS 16 bridge
logs show the helper executing and certificate checks passing at this location.
The iOS 15 symbol-resolution problem in issue #2 is a separate compatibility
step. SIGKILL alone does not identify the original kernel rejection mechanism.

Wi-Fi host-key failures distinguish an unreachable route, a refused SSH port,
and a missing response. USB failures retain USB-specific guidance. The app
includes a local-network purpose string. These diagnostics do not change SSH
trust or bypass host-key verification.

## Dopamine with RootHide

**RootHide is currently unsupported by Mirra.** The existing path converters
and separate code/data layout are implementation work, not verified jailbreak
compatibility. Creating a helper directory, switching SSH accounts or launching
the helper does not establish working attestation and Mirroring authentication.
Use a compatible bridge with an active supported jailbreak.

Existing profiles may contain `backend.ssh.path_mode: "roothide"`. Mirra retains
their path handling for investigation and to preserve saved configuration; this
does not change RootHide's unsupported status.

See RootHide's documentation for
[code locations and entitlements](https://github.com/roothide/Developer/blob/main/entitlements.md),
[bootstrap paths](https://github.com/roothide/Developer/blob/main/roothide.md) and
[path conversion](https://github.com/roothide/Developer/blob/main/interface.md).

## Test a bridge

1. Install the app on a [compatible host](../README.md#compatibility).
2. In Settings, open setup, select the bridge and verify its SSH fingerprint.
3. Choose **Prepare connection** and check helper signing, capabilities,
   certificate preparation and attested-key validation.
4. Finish setup and connect the locked target through Apple's app.
5. Check authentication, screen output, input, audio and reconnection.

Record the device, OS, jailbreak, transport and Mirra version with the results.
If a helper fails before certificate preparation, inspect its launch/signing
error rather than requesting another certificate.

For an additional bridge diagnostic with an app installed in Applications:

```sh
"/Applications/Mirra.app/Contents/Resources/Support/python/bin/python3" -B \
  "/Applications/Mirra.app/Contents/Resources/Support/scripts/doctor.py" \
  --config "$HOME/Library/Application Support/Mirra/current/config.json" \
  --backend --json
```

This starts the endpoint and checks a disposable key and certificate binding.
Errors preserve the native status, failed keystore stage and selected bridge
capabilities, without including the generated key or identity. A passing result
does not test the target's authentication or the complete SEP session.
Keep the setup directory private and share only relevant redacted errors.
