# Keystore symbol loading

The phone endpoint loads AppleKeyStore functions through `load_keystore` in
`src/phone/endpoint.m`. Normal exported symbols always take priority. When a
required export is missing, the same loader resolves the function from the
loaded system images or the active dyld cache's symbol data before adding it
to the existing missing-symbol report.
The protocol endpoint and device self-check use the same typed `KeyStore` API.

## iOS 15 symbol discovery

Every iOS 15 build uses the same discovery path, including arm64 and arm64e
caches. There is no list of permitted minor versions or builds. If the product
version query is unavailable, the loader recognizes the iOS 15 product-build
family. Other iOS versions retain their existing exported-symbol lookup.

The loader checks exports in MobileKeyBag, CryptoTokenKit and AppleKeyStore,
then tries the existing verified map and the loaded images' `LC_SYMTAB` tables.
If the required local symbols are not mapped, it reads the active cache's
inline local symbols or its `.symbols` companion. Cache UUIDs must match the
running process; companion UUIDs must match the active cache's declaration.
The reader handles both 32-bit file-offset and 64-bit VM-offset entry formats.
It uses the current cache's symbol addresses, not offsets from another build.

Each returned address must belong to the selected loaded image's executable
`__TEXT,__text` section, with the correct symbol section index and instruction
alignment. Bounds, arithmetic, symbol types, image metadata and ambiguous
definitions are checked before a function can be used. Arm64e callers receive
authenticated function pointers. Cache files are opened read-only, and their
size, type, ownership and permissions are checked before mapping symbol data.

`--capabilities` includes `keystore_resolution` diagnostics for iOS 15. Missing
or mismatched cache data and unresolved functions keep the endpoint unavailable;
the original error codes, missing-symbol list and protocol remain unchanged.

The format reader is project-authored code based on Apple's
[dyld 852.2 format](https://github.com/apple-oss-distributions/dyld/blob/dyld-852.2/dyld3/shared-cache/dyld_cache_format.h)
and [dyld 955 local-symbol reader](https://github.com/apple-oss-distributions/dyld/blob/dyld-955/common/DyldSharedCache.cpp).
No Apple cache files or symbol tables are distributed with Mirra.

## Existing verified map

The map in `src/phone/keystore-symbols.h` comes from
[@OiviaDesu](https://github.com/OiviaDesu)'s
[PR #4](https://github.com/eiyuumiru/Mirra/pull/4), commit `a193c167`.
It contains 14 MobileKeyBag functions and four CryptoTokenKit parameter functions.
The fallback requires iOS build `19H422` (15.8.8), generic arm64, the exact loaded
image paths and UUIDs, and aligned addresses in executable `__TEXT,__text`.
Malformed metadata, other builds and arm64e are rejected by this fixed map.
They can use symbol discovery when their actual symbol data is available.
The endpoint reuses its existing platform queries and keeps loaded image
handles alive.

This is part of the normal endpoint build. There is no alternate endpoint or
OS-specific build option. Existing exports, certificate handling, session
ownership and request/reply behavior remain on the existing path. Applying
discovery to all iOS 15 builds does not establish that every device exposes the
required private APIs or that every private operation succeeds.

The ordinary endpoint compiler also uses the map with its reviewed import-stub
fallback, and records both resolver-header hashes in the build report. The dyld and C
imports are bounded by the existing allowlist; unknown imports remain errors.

## Checks

```sh
make symbols
```

Host fixtures cover original symbol priority, missing-symbol reporting, shared
API loading, image/CPU mismatches, command bounds, address arithmetic and owned
session cleanup. Cache fixtures also exercise different function addresses,
both entry formats, inline and companion files, loaded symbol tables, UUID
mismatches and malformed data. The production dyld API bindings are checked on
the host. These fixtures never execute a private keystore function.

With a full iPhoneOS SDK, `make build/endpoint-check` builds the device self-check.
Sign it on the bridge with `ldid` and `config/endpoint.plist`, as for the normal
endpoint. It loads the production API, creates and unloads one unsaved keybag,
generates a signing key and serializes parameters. It never uses system keybags
or prints key material. macOS is rejected before any keybag calls.

## Device evidence

@OiviaDesu reports symbol resolution, keybag/parameter checks, certificate export,
attested-key generation and provisioning on iPhone 6s Plus (`iPhone8,2`), iOS
15.8.8 (`19H422`), Dopamine rootless (version not recorded), over SSH.
The contributor later [confirmed the integrated v0.1.1 loader](https://github.com/eiyuumiru/Mirra/issues/2#issuecomment-6787375003)
completed signing, both unlock steps and confirmation during a live connection
on that device/build. The [successful connection](https://github.com/eiyuumiru/Mirra/issues/3#issuecomment-6787375682)
also used a separate local OCLP media correction on MacBookPro10,1 (`25G332`).
The new discovery path has host and compiler validation; physical-device
validation on other iOS 15 builds is still needed.

[Issue #1](https://github.com/eiyuumiru/Mirra/issues/1) concerns helper execution
paths; [issue #2](https://github.com/eiyuumiru/Mirra/issues/2) concerns missing
symbols. The OCLP crash in [issue #3](https://github.com/eiyuumiru/Mirra/issues/3)
is covered in [Media transport](Media.md). These are separate failures.
