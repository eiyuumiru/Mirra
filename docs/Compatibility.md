# Compatibility matrix

Mirra remains experimental. The reference host is Intel macOS 26.7.2
(`25G332`) with Apple's iPhone Mirroring 1.6 (`98.5`); the reference bridge is
iPhone XS on iOS 17.2. A successful report establishes that configuration and
attempt, not every device in the same family. The tables below distinguish
project requirements from upstream driver capabilities and unverified cases.
The upstream documentation was reviewed on 15 November 2026.

## Connection stages

| Stage | Required capability | What a passing preliminary check leaves unverified |
| --- | --- | --- |
| Host startup | Intel macOS 15+, Apple's installed 1.x app, compatible private interfaces, usable native injection permissions | Actual behavior of private APIs, driver compatibility and the target connection |
| Bridge launch | Active compatible jailbreak, arm64 iOS 15+, verified SSH, signed executable in an allowed location | Device certificate and SEP operations |
| Bridge identity | Matching certificate; successful attested generation, validation and supported wire layout | Signing and the complete remote SEP session |
| Target discovery and authentication | Apple's target/account requirements, Wi-Fi, BLE discovery and return authentication | Screen transport, rendering, audio and input |
| Media | AWDL transport, H.264 VideoToolbox decoding and usable graphics rendering | Sustained frame rate, color/profile handling and reconnect reliability |
| Lifecycle | Owned launch registrations and successful restoration after stop/update | Sleep/wake, login restoration, physical disconnection and long-running use on each configuration |

The bridge and target are separate iPhones. USB SSH to the bridge changes its
transport only; it does not replace the target's Wi-Fi/Bluetooth requirements.
Successful AirDrop, Handoff or Universal Clipboard can narrow a radio problem,
but does not verify every Mirroring discovery or authentication operation.

## Host OS and model

| Configuration | Current boundary |
| --- | --- |
| Intel macOS 15 Sequoia | Experimental. Accepted only when the required interfaces match; the Tahoe-specific decoder hook remains off in automatic mode |
| Intel macOS 26 Tahoe | The inspected `25G332` configuration is the reference; other builds require interface and live connection validation |
| Newer macOS builds | Version acceptance is not a support guarantee; private implementation changes can require new investigation |
| Apple silicon or macOS earlier than 15 | Outside the current Intel host implementation |
| OCLP hosts | The guarded RemoteScreen stub repair addresses the reported constant-return failure; it does not repair every root-patched graphics or radio stack |
| SIP fully enabled | Currently unsupported; see [Installation](Installation.md#system-integrity-protection-sip) |
| SIP disabled or partially enabled | Native support still needs usable injection and launch permissions; a general SIP status is not a complete permission test |
| SMBIOS variants, including iMac19,1 and iMac20,x | Model identification alone cannot establish graphics, radio or authentication compatibility. A T2-era SMBIOS does not supply physical T2 hardware |

An unexplained connection timeout is not evidence that Sequoia is its cause.
Do not prescribe a macOS 26 upgrade as a confirmed repair. A comparison on a
separate installation can be useful once that OS supports the host's complete
driver stack; it should preserve a working configuration for comparison.

## Graphics and decoding

| Driver family | Required checks and limits |
| --- | --- |
| Apple-supported Intel graphics with WhateverGreen | Correct framebuffer/device configuration and available VideoToolbox decoder. A headless iGPU can provide decoding while another GPU renders; the SMBIOS alone does not prove either path |
| Apple-supported AMD graphics with WhateverGreen | Verify the installed accelerator and actual H.264 decode on that OS. Display output and a working desktop do not establish decoder/profile compatibility |
| OCLP legacy graphics, including legacy Intel/AMD/NVIDIA | Capability varies by patch set and OS. Metal and codec support must be assessed separately; an OCLP media repair is not proof of graphics acceleration |
| HighDelay/NullMoth NVIDIA Metal variants | Metal and video codec components are separate. Identify the installed fork/package and OS, then test public decoding and the native stream; gaming or Vulkan success does not verify VideoToolbox |
| Other community accelerators, software rendering or unsupported GPUs | Unverified. A Metal device name, decoder session or claimed hardware property alone does not prove usable Mirroring output |

Mirra's decoder hook addresses the inspected Display P3/FLS creation failure on
`25G332`. It preserves compressed samples and stream metadata, and applies only
to the selected supported policy. See [Decoder](Decoder.md) for exact matching
and restoration behavior. A small Baseline frame does not exercise this path.

Graphics configuration belongs to the GPU/patch project's supported OS and
hardware instructions. Mirra does not install drivers or infer a repair from a
GPU name. See [WhateverGreen][weg], its [Intel][intel-gpu] and [AMD][amd-gpu]
guides, [OCLP graphics][oclp-gpu], and the reviewed [NVIDIA fork][nvidia].

## Wi-Fi and Bluetooth

Wi-Fi and Bluetooth are separate parts of a combo card. Firmware loading,
pairing/audio, BLE advertising and AWDL are separate observations.

| Radio family | Current boundary |
| --- | --- |
| Native Apple Broadcom Wi-Fi/Bluetooth | A useful reference when supported by the installed OS; still requires a live target connection and account checks |
| Third-party Broadcom Wi-Fi with AirportBrcmFixup or root patches | Support depends on the PCI device, OS and patch set. Working association does not prove AWDL or Mirroring |
| Broadcom RAMUSB Bluetooth with BrcmPatchRAM | Firmware must match the USB controller. Modern macOS uses the applicable BlueToolFixup/Lilu combination; the legacy BrcmBluetoothInjector is not for macOS 12+ |
| BCM94352HMB and similar combo cards | Validate Wi-Fi and Bluetooth separately. There is no confirmed general Mirra fix based only on this card's name or the macOS major version |
| Intel Wi-Fi with itlwm | The documented Ethernet-style implementation does not provide Mirra's required AWDL Wi-Fi path by itself |
| Intel Wi-Fi with AirportItlwm | Upstream documents limited Handoff/Clipboard support, not complete Continuity/AWDL. Treat native Mirroring as unverified rather than inferring support from those features |
| Intel Bluetooth firmware/patcher variants | Firmware preparation and scanning fixes do not supply an independently complete Bluetooth stack. Verify the controller, firmware, OS and upstream-supported kext combination |
| MediaTek MT7921/MT7922 with MtkWireless | The reviewed Wi-Fi implementation targets Tahoe and records AWDL/Continuity observations on specific builds. These do not establish every hardware variant or SEP/decoder path; Sequoia is not its documented Wi-Fi target |
| Other Qualcomm/Atheros/Realtek radios, USB Wi-Fi and USB Bluetooth dongles | Unverified as complete Mirroring configurations. Generic network or Bluetooth audio support does not establish AWDL and BLE return authentication |

An `awdl0` interface with IPv6 confirms local configuration, not successful
peer traffic. A loaded firmware kext does not prove that the controller accepted
its firmware. A Bluetooth power indicator or cleared startup failure flag does
not prove successful advertising or L2CAP authentication.

Use the upstream [AirportBrcmFixup][airport-brcm], [BrcmPatchRAM][brcm],
[OpenCore feature flags][opencore], [Intel Wi-Fi FAQ][intel-wifi],
[Intel Bluetooth installation][intel-bt-install] and [FAQ][intel-bt-faq], and
[MtkWireless][mtk] documentation for the installed versions. Driver and firmware
changes require separate evidence; Mirra's diagnostics do not apply them.

## Bridge iPhone

| Configuration | Current boundary |
| --- | --- |
| Compatible arm64 bridge, active jailbreak, iOS 15+ | Must run the helper and complete certificate, attestation and remote-session operations; age/model/OS alone is insufficient |
| Generic arm64 helper on an arm64e device | CPU target compatibility is only one step. Private API and SEP behavior still require validation on that jailbreak/build |
| iOS 15 symbol discovery | Normal exports take priority; guarded loaded-image/cache discovery covers iOS 15. The fixed fallback map is only for `19H422` and matching image UUIDs |
| Standard rootful/rootless jailbreak layouts | Existing signing and allowed executable placement apply. A working rootless layout is not proof that every jailbreak permits attestation |
| A11 configurations with jailbreak SEP restrictions | Restricted SEP/passcode behavior can block operations even after helper launch or key generation. Mirra does not bypass the restriction |
| RootHide | Currently unsupported. Retained filesystem path handling does not establish working attestation and authentication |
| iOS earlier than 15, missing jailbreak or unavailable required APIs | Outside the current bridge requirements |

`--backend` creates and validates a disposable key. It does not verify signing,
remote peer confirmation or all native SEP session operations. A reported native
status identifies a failed operation; it is not a diagnosis of every possible
cause of that status. Use a compatible bridge when SEP is unavailable.

See [Bridges](Bridges.md), [KeyStore](KeyStore.md), the reviewed
[Dopamine source][dopamine], [palera1n requirements][palera1n] and
[RootHide development model][roothide]. Mirra troubleshooting should not
automatically reset a phone or weaken its security configuration.

## Target iPhone

The target needs iOS 18 or later, a passcode, the same Apple Account with
two-factor authentication, Wi-Fi and Bluetooth enabled, and a nearby locked
screen. Complete Apple's setup/unlock instructions before locking it again.
The target does not require a jailbreak. Apple's availability/region and
simultaneous-use restrictions still apply, including conflicting AirPlay,
Sidecar or Internet Sharing sessions; restrictive VPN or firewall settings can
also affect the connection. Check the current [Apple requirements][apple].

An unlocked target, incomplete setup prompt, missing return pairing request,
SEP failure and decoder failure are different states. Report the stage and
messages from the same attempt rather than combining them into one timeout.

## Optional host observations

From a source checkout after building the inspector:

```sh
python3 scripts/doctor.py --hardware --json
```

For an app that includes this diagnostic and is installed in Applications:

```sh
"/Applications/Mirra.app/Contents/Resources/Support/python/bin/python3" -B \
  "/Applications/Mirra.app/Contents/Resources/Support/scripts/doctor.py" \
  --config "$HOME/Library/Application Support/Mirra/current/config.json" \
  --hardware --json
```

This option uses bounded read-only queries and does not restart services, alter
drivers, change SIP or open a bridge connection. `--backend` is separate and
does create a disposable bridge key. Hardware observations do not change Connect
readiness or the doctor's existing prerequisite exit result.

The report selects OS/model, Metal device names, local Bluetooth controller
fields, local Wi-Fi card/firmware descriptions, controller-to-interface bindings,
matching loaded kext IDs/versions, AWDL/LLW flags and SIP state. PCI vendor/device
IDs are included only when IORegistry directly associates the controller with a
PCI device. AirPort's reported card description is preserved as text, since its
hex values may identify a board or subsystem instead. Ambiguous bindings remain
unknown; controller classes and bundle versions do not prove driver-fork origin.
The report excludes
paired-device inventories, Bluetooth addresses, SSIDs, raw boot arguments,
certificate/key data and command error text. Missing or failed queries stay
unknown. Loaded kexts are an incomplete inventory: codeless injections, root
patches and user-space driver packages may not appear.

The graphics probe decodes an original 64×64 Baseline H.264 sample through
default and hardware-required public VideoToolbox sessions, recording actual
frame output and the reported hardware property. Where available, the session's
GPU registry property is matched locally to a Metal device name; registry IDs
are not exported. This identifies the fixture's GPU, not native Mirroring's GPU.
It does not test Display P3/FLS,
the native target stream, graphics presentation, audio, sustained throughput or
sleep/wake. A passing fixture is preliminary evidence, not a stability claim.

## Validation scope

Python regressions and native fixtures cover configuration, protocol, symbol
guards, wire layout, error reporting, ownership and restoration. They do not
replace physical-device tests. Before declaring a new configuration stable,
validate initial setup, native authentication, video/audio/input, reconnect,
bridge disconnection, sleep/wake, login restoration and an update/stop cycle.
Record the exact OS builds, jailbreak and driver versions with each result.

[weg]: https://github.com/acidanthera/WhateverGreen/blob/093e76fec5655001f38b367dd22459c756ee89fa/README.md
[intel-gpu]: https://github.com/acidanthera/WhateverGreen/blob/093e76fec5655001f38b367dd22459c756ee89fa/Manual/FAQ.IntelHD.en.md
[amd-gpu]: https://github.com/acidanthera/WhateverGreen/blob/093e76fec5655001f38b367dd22459c756ee89fa/Manual/FAQ.Radeon.en.md
[oclp-gpu]: https://dortania.github.io/OpenCore-Legacy-Patcher/ACCEL.html
[nvidia]: https://github.com/HighDelay/nvidia-macos-driver/blob/22d10387daeb5e5c7510006af0bb44d6b93bdd8f/README.md
[airport-brcm]: https://github.com/acidanthera/AirportBrcmFixup/blob/a5f0628e6d878e9dbb3ac7cce3bcb6d18dd80887/README.md
[brcm]: https://github.com/acidanthera/BrcmPatchRAM/blob/65389020769837e92e9fb939bac34bd9a3e25bb2/README.md
[opencore]: https://github.com/acidanthera/OpenCorePkg/blob/ebea824880706ac9faa8ee45604245de62be658b/Docs/Configuration.tex
[intel-wifi]: https://openintelwireless.github.io/itlwm/FAQ.html
[intel-bt-install]: https://openintelwireless.github.io/IntelBluetoothFirmware/Installation.html
[intel-bt-faq]: https://openintelwireless.github.io/IntelBluetoothFirmware/FAQ.html
[mtk]: https://github.com/Dino-VN/MtkWireless/blob/b92a31a0c61cb0eed86a7933071d7055e46dc738/README.md
[dopamine]: https://github.com/opa334/Dopamine/blob/5b1d2c1c3bf54dd8e3641d29c60cd3a0c13cde88/README.md
[palera1n]: https://github.com/palera1n/palera1n/blob/3ba32c40dbd90b9bcff1a71b5f9ee26c3388b0ad/README.md
[roothide]: https://github.com/roothide/Developer/blob/c53cc199f1bab7d7ea2fd70f0a14e215b1f3461b/README.md
[apple]: https://support.apple.com/en-us/120421
