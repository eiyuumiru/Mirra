# Release guide

`VERSION` supplies the release version. `config/release.json` supplies internal
bundle metadata and the repository URL. Package filenames use that version.

The release version is **0.2.0**. Its changes are recorded in the
[changelog](../CHANGELOG.md#020). Local packages can be built and staged for
review; tagging and publication are separate steps.

## Prepare

- Update the changelog and compatibility documentation for the change.
- Run relevant source and native checks, plus device tests for runtime changes.
- Record the host's SIP configuration with live test results. Fully enabled SIP
  is currently unsupported; use disabled or compatible partially enabled SIP.
- Build from a clean checkout or the source for the selected release tag.
- Check the app signature, bundled runtime and third-party notices.
- Mount the DMG, verify the Applications shortcut and test app relocation.
- Review screenshots and exported files for private data.

## Build the DMG

```sh
make package
```

The command creates `Mirra-v<version>.dmg` under `dist/app` and prints its SHA-256.
Stage the selected DMG under `dist/v<version>/` alongside `SHA256SUMS` and
`RELEASE-NOTES.md`, following the v0.1.0 release layout. Keep internal build
numbers out of release asset names. The internal bundle number advances once
per release: v0.1.0 uses 31, v0.1.1 uses 32, v0.1.2 uses 33, v0.1.3 uses 34 and v0.2.0 uses 35.

## Release signing

The local v0.2.0 build uses ad-hoc signing and is not notarized. It has not
been published by the build or verification commands.

The v0.1.3 distribution uses a persistent self-signed certificate. It is not an
Apple Developer ID and the app is not notarized. Signature verification checks
integrity; it does not establish Apple trust or guarantee that Gatekeeper will
retain an earlier approval. Keep the certificate's private key and keychain
password outside the repository and release assets.

`make package` produces an ad-hoc signed local build. For the self-signed
distribution, run `make app`, sign every bundled macOS binary with the selected
identity while preserving its identifier, entitlements and flags, then refresh
the Python and support hash manifests. Preserve the arm64 iOS endpoint: it is
signed separately on the bridge. Restore the bundled runtime's read-only
permissions, sign the outer app last, and verify all signatures, manifests and
deployment targets.

Package that existing signed app with `python3 scripts/package.py`. Running
`make package` afterward rebuilds the app with ad-hoc signing. Verify signatures
and the bundled runtime again after copying the app from the mounted DMG and
ejecting the image.

## Publish

Review the staged source, Git identity and repository remote before committing.
Keep generated builds, private profiles and runtime logs out of version control.
Tag the selected version and attach the app DMG and checksum file to the release.
GitHub automatically provides **Source code (zip)** and **Source code (tar.gz)**
downloads for that tag.

Build and packaging commands create local files; publication is a separate step.
Release notes should identify Mirra as experimental and describe the change,
tested configurations, compatibility limits and signing status. Use the DMG to
install the app and GitHub's source downloads to build it.

See [Publishing](Publishing.md), [Distribution](Distribution.md) and
[Screenshots](Screenshots.md).
