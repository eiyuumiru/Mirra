# Contributing

Mirra depends on private macOS interfaces. Contributions should describe the
problem, the resulting behavior and the evidence supporting the change.
Original source contributions use the [MIT License](LICENSE); retain applicable
third-party notices.

## Report a bug

Include the Mirra version, macOS version and build, host model and SIP status,
Wi-Fi/video drivers, bridge model and jailbreak, target iOS, and connection
transport. Include the package checksum when available. State whether setup,
discovery, authentication, video or input failed and how to reproduce it.

Check the [host SIP requirement](docs/Installation.md#system-integrity-protection-sip)
before testing: fully enabled SIP is currently unsupported. Report the partial
configuration when using partially enabled SIP.

Keep logs from the same attempt and redact credentials, account information,
device identifiers and personal content before sharing. See [SECURITY.md](SECURITY.md).

## Develop a change

Run checks relevant to the change using the [build guide](docs/Build.md).
Changes to bridge, decoder or service behavior also need tests on the affected
devices. Describe which checks ran and any remaining limitations.

Keep status observation read-only and preserve service ownership and cleanup
rules. Read [Architecture](docs/Architecture.md) before changing runtime behavior.

Add distributable files to `config/sources.json`. Keep credentials, generated
builds and private reports outside the source export. See
[Distribution](docs/Distribution.md) for package verification.
