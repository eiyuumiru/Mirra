# Connection checks

Before opening iPhone Mirroring, Mirra checks the configured bridge's process
lifetime, endpoint health and launch support. Status must belong to the current
service session. If ready, Mirra opens Apple's app; otherwise, a native dialog
offers recovery guidance and access to logs.

The health observation does not change service state. Unavailable observations
remain unknown rather than authorizing a restart.

Apple's app handles target discovery, radio requirements, account checks and
remote unlock. Mirra does not add a target confirmation or Bluetooth-power gate.
Bridge readiness and a connected target screen are different states.

Before connecting, check the macOS host's
[SIP configuration](Installation.md#system-integrity-protection-sip). Fully
enabled SIP is currently unsupported; use disabled or compatible partially
enabled SIP. A ready bridge does not confirm that the host's SIP configuration
permits native support.

For setup or connection failures, use **Show Log** and inspect the failing
attempt. See [App guide](App.md) and [Background support](Service.md).
