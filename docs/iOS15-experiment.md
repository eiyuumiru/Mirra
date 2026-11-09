# iOS 15.8.8 AKS resolver experiment

This is an opt-in, device-tested experiment, not general iOS 15 support.
Default builds remain unchanged. Define `MIRRA_EXPERIMENTAL_IOS15` to enable
fallback resolution when the normal AppleKeyStore lookup fails.

## Scope and guards

The fallback accepts arm64 (not arm64e), OS build `19H422`, and exact
MobileKeyBag/CryptoTokenKit image UUIDs. Fourteen AKS functions are private
symbols in MobileKeyBag; four `aks_params_*` functions are in CryptoTokenKit.
Offsets were obtained from the matching device's dyld shared cache and its
local-symbols companion using `ipsw dyld symaddr`. `ipsw dyld macho` provides
the image UUID and preferred __TEXT base. Subtract that base from each symbol
address to obtain the offset. At runtime, add the offset to the loaded image
header, handling ASLR, then require an aligned address in executable __TEXT.
No Apple binaries, caches, certificates or device identifiers are included.

An OS/build or UUID mismatch fails closed. Do not relax the guards to make
another device pass. Private function signatures and behavior require separate
validation; resolving an address is not proof that every API works.

## Build and device self-check

A full iPhoneOS SDK is required; the macOS-header/import-stub fallback is not
supported for this experiment. From the repository root:

```sh
SDK=$(xcrun --sdk iphoneos --show-sdk-path)
mkdir -p build
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -isysroot "$SDK" -fobjc-arc -fblocks -Wall -Wextra -DMIRRA_EXPERIMENTAL_IOS15 src/phone/endpoint.m -framework Foundation -framework Security -o build/endpoint-ios15
xcrun --sdk iphoneos clang -target arm64-apple-ios15.0 -isysroot "$SDK" -fobjc-arc -fblocks -Wall -Wextra tests/ios15-symbols.m -framework Foundation -framework Security -o build/ios15-selfcheck
```

Copy the binaries and `config/endpoint.plist` to a private executable path
supported by the jailbreak. Sign each binary on-device with
`ldid -S/path/to/endpoint.plist /path/to/binary`, then run the endpoint with
`--capabilities` and run `ios15-selfcheck` separately. Do not compile the
self-check with `NDEBUG`: it rejects that configuration at compile time because
its assertions execute and verify the API calls.

The self-check creates and unloads an unsaved keybag, generates a signing key,
and serializes AKS parameters. It does not access system keybags.

## Observed results and limitations

Device: iPhone 6s Plus (`iPhone8,2`), iOS 15.8.8 (`19H422`), Dopamine rootless
(exact jailbreak version not recorded), SSH transport.

- All 18 required symbols resolve.
- Self-check: create_bag=0, create_signing_key=0 (73 bytes), unload_bag=0,
  params_roundtrip=ok (26 bytes), PASS.
- Cached certificate export: 1318 bytes; no issuance requested.
- Attested-key generation: status 0, 2041 bytes; endpoint exited cleanly.
- App integration: provisioning and installation passed; bridge reports ready.
- Python regression suite: all 268 tests passed on the pre-PR rerun. Two
  earlier runs timed out in the slow-reset transport test at its 0.14-second
  initial-read deadline on the same Mac.
- End-to-end mirroring is blocked by a Mac-side crash in
  WiFiPeerToPeerOld.dylib on the OCLP MacBookPro10,1, macOS 26.7.2 (25G332).
  Apple's iPhone Mirroring requires the T2 chip for device attestation
  (https://oclp.dev/features/). No OCLP Mac has a T2; this is a hardware
  limitation, not a bridge or resolver issue.
- Remote-session handshake, screen output, input and notification delivery
  are not verified. Wrong-build/UUID rejection has not been device-tested.

Normal `make endpoint` does not enable this experiment. Rootless deployment
path handling and the Mac-side crash are separate issues, not fixed here.
