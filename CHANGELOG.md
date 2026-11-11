# Changelog

## 0.1.2

- Correct the OCLP RemoteScreen export lookup through `dlsym`, contributed by
  [@OiviaDesu](https://github.com/OiviaDesu) in
  [PR #5](https://github.com/eiyuumiru/Mirra/pull/5). The earlier lookup used the
  Mach-O underscore prefix and could miss the export, leaving the reported
  Mirroring crash after bridge setup unchanged. The existing exact-stub, method
  signature and object-ownership guards remain in place.
- Extend the existing keystore loader's missing-symbol discovery to every iOS 15
  build, including arm64e caches. Keep exported symbols first and the existing
  verified `19H422` map, then resolve functions from loaded image tables or the
  active dyld cache's inline or companion symbol data. Check UUIDs, file metadata,
  table bounds, executable sections and function addresses before using them.
  The bridge protocol, certificate operations and missing-symbol errors are
  preserved. See [Keystore loading](docs/KeyStore.md) for limits and attribution.
- Recover an abandoned sharingd registration when its recorded runtime directory
  or plist has disappeared. Verify the private journal and loaded job's exact
  adapter and log paths, then confirm restoration of the original registration
  before clearing recovery state. Keep live-owner, child-process, session-lock
  and workspace-lease checks. Recover stopped support before updating it while
  preserving the saved bridge and failed-attempt diagnostics.
- Wait when Apple's iPhone Mirroring is already open before support starts,
  then continue automatically in the same support process after the app quits.
  Show a Command-Q instruction with Check again and Stop. Preserve deliberate
  recovery for failed or interrupted preparation and existing ownership and
  abandoned-session cleanup checks.

The AWDL fixtures now exercise the public class and exported-symbol lookup, so
the previous underscored lookup fails the regression check. @OiviaDesu reported
a successful connection with the OCLP correction on the affected MacBookPro10,1
(`25G332`) and iPhone8,2 bridge (`19H422`). That local retest is recorded in
[issue #3](https://github.com/eiyuumiru/Mirra/issues/3#issuecomment-6787375682).
The broader iOS 15 discovery and missing-runtime recovery have fixture validation;
physical-device confirmation on other iOS 15 builds and the affected recovery
configuration is still needed. Startup waiting, cancellation and failure
preservation have process and fixture validation; login-restoration and device
retesting of the rebuilt DMG are still needed. Bridge iPhones require a
compatible active jailbreak and **iOS 15 or later**.

On the macOS host, Mirra requires SIP disabled or a compatible partially enabled
configuration. Fully enabled SIP is currently unsupported. See
[SIP configuration](docs/Installation.md#system-integrity-protection-sip).

## 0.1.1

- Recover pending app-launch, decoder and sharing sessions before updating
  stopped support, preserving ownership checks and the saved bridge setup.
- Fix control-error logging so an unsuccessful action returns its error reply
  without a second Python exception.
- Pause failed startup attempts instead of repeating permission prompts, and
  verify cleanup before trying to restore launch support.
- Place default rootless bridge helpers inside the detected jailbreak bootstrap,
  preserving existing deployments, custom roots and RootHide handling.
- Distinguish unreachable SSH routes, refused ports and missing responses while
  preserving host-key verification.
- Extend the existing keystore loader with the guarded symbol-map fallback and
  shared device self-check, contributed by [@OiviaDesu](https://github.com/OiviaDesu)
  in [PR #4](https://github.com/eiyuumiru/Mirra/pull/4). See [Keystore loading](docs/KeyStore.md).
- Repair the known OCLP RemoteScreen constant stub with guarded method patching,
  based on [@OiviaDesu](https://github.com/OiviaDesu)'s
  [PR #4](https://github.com/eiyuumiru/Mirra/pull/4) repair.
- Target Intel macOS 15 or later for the app and every bundled macOS helper.
  Verify binary deployment targets during app building and packaging.
- Allow experimental Sequoia setup with Apple's Mirroring 1.x app when the
  required private interfaces match. Keep the tested Tahoe decoder policy.
- Apply automatic decoder compatibility to Display P3/FLS H.264 streams on the
  supported Intel build, regardless of Mac model. This addresses connection
  failures where video arrives but decoder creation repeatedly returns `-8969`.
- Preserve bridge support while AVConference is idle or restarting, and wait for
  a fresh decoder hook marker before reporting an active decoder as ready.
- Restore the original AVConference registration before an automatic decoder
  fallback after a failed route change.

Bridge iPhones require **iOS 15 or later** and a compatible active jailbreak.
Sequoia connections and the integrated iOS 15 keystore fallback still need
device validation.

## 0.1.0

- Guided SSH and USB bridge setup, host-key verification and certificate preparation.
- Rootless and RootHide deployment support.
- Background service with connection recovery and verified cleanup.
- Media transport and decoder compatibility adapters.
- Compact interface with Settings, appearance options and native error dialogs.
- Live logs, dated files, seven-day retention and a log-folder action.
- App version in Settings and About.
- DMG installation with an Applications shortcut and a bundled Python runtime.
- Documentation, demo images, GitHub source downloads and third-party notices.
