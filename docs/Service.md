# Background support

The per-user LaunchAgent starts `mirra-cli run-service` at macOS login. The CLI
starts the existing supervisor with the saved bridge profile and enables
automatic reconnection. Once support is ready, open Apple's iPhone Mirroring
directly. Guided setup installs the job and the CLI into Mirra's Application Support.

## Install and control

The CLI in the app bundle can inspect and control the installed service:

```sh
"/Applications/Mirra.app/Contents/Resources/Support/build/mirra-cli" control status
```

Native support requires SIP disabled or a compatible partially enabled
configuration on the macOS host. Fully enabled SIP is currently unsupported;
see [SIP configuration](Installation.md#system-integrity-protection-sip).

Stop competing support processes and USB proxies before installation.

```sh
python3 scripts/service.py prepare --config PATH
python3 scripts/service.py install
python3 scripts/service.py status
```

`prepare` creates a private package and launch definition. `install` registers
and starts the job. The package contains a configuration snapshot; editing the
source profile does not change a running service.

Status reports registration, native launch support and bridge health. Readiness
requires matching live process identities. It does not establish target video.

When the bridge certificate expires, support checks the enrolled bridge for a
current replacement and requests renewal if needed. If the issuer still returns
an expired certificate, Mirra reports it and waits 15 minutes before requesting
issuance again.

Choose **Renew Now** in Mirra or run the following command to request renewal
immediately. Mirra checks for a valid certificate on the enrolled bridge first
and reports the outcome.

```sh
"/Applications/Mirra.app/Contents/Resources/Support/build/mirra-cli" control renew
```

When `control status` or `control renew` reports `bridge_update_available`,
choose **Update Bridge** in Mirra. With a saved SSH account that already has
installation privileges, the bundled CLI can also perform the update.

```sh
"/Applications/Mirra.app/Contents/Resources/Support/build/mirra-cli" setup update-bridge </dev/null
```

```sh
python3 scripts/service.py stop
python3 scripts/service.py start
python3 scripts/service.py remove
```

`stop` unloads support and waits for cleanup while retaining login registration.
`start` loads it again. `remove` stops support and removes the owned registration,
preserving private setup, logs and the installed package.

If Apple's iPhone Mirroring is already open when background support starts,
Mirra checks the Mac and then waits for the Apple app to quit before preparing
a session. Mirra shows **Quit
iPhone Mirroring**: use Command-Q in Apple's app, then wait for Mirra to become
ready. Startup continues automatically in the same support process. Stop still
cancels this wait. Closing only the app's window may leave it running.

After background recovery replaces sharingd, Mirra also checks whether an owned
iPhone Mirroring process predates that replacement. If so, quit Apple's app with
Command-Q and reconnect after Mirra becomes ready. This closes connections left
over from the earlier support session. Connect preflight retains the same
instruction.

Earlier v0.1.2 builds predate this startup recovery change. If they encounter
this order of startup, support stays paused even after Apple's app quits. Quit
iPhone Mirroring, open Mirra's Settings, choose **Stop**, wait for shutdown, then
choose **Start**. Wait for readiness before opening iPhone Mirroring again. This
case records `Close the existing Mirroring app before starting a native session`
and `NATIVE_STARTUP_PAUSED` in the service log.

## macOS data-access prompts

The native socket helper uses a temporary directory inside iPhone Mirroring's
container. macOS may ask whether `python3` can access data from other apps; the
request belongs to Mirra's bundled background interpreter. The permission can
expire when that interpreter exits. It is not an iPhone jailbreak or T2 check.

If startup fails, support now waits without retrying in the same interpreter.
The window shows the failure and a recovery action instead of staying on
"Preparing app support". Go back to Settings, stop support, then start it to
retry deliberately. Allow the macOS request if you want Mirra to use that
temporary directory. If the folder is missing, open and quit Apple's iPhone
Mirroring once before retrying. A later startup error still needs its own
diagnosis in the service log; granting file access does not prove readiness.

An interrupted preparation is also held on the next launchd invocation. A normal
stop rearms it. Waiting for iPhone Mirroring to quit can resume after a support
restart because session preparation has not begun. Bridge reconnection inside
a running native session remains automatic. No Full Disk Access grant or
privacy-database changes are required by this fix. See Apple's
[macOS app-data privacy explanation](https://developer.apple.com/videos/play/wwdc2023/10053/).

## Update or switch profiles

```sh
python3 scripts/service.py stop
python3 scripts/service.py prepare --replace
python3 scripts/service.py install
```

Without `--config`, replacement preserves the installed profile and credentials.
Add `--config PATH` to select another bridge. Cleanup must finish before replacement.
The previous package is archived for rollback.

Installations from before service pairing need a paired bridge profile from Setup
before updating. Mirra preserves their existing support and credentials. It also
checks that the selected pairing token and certificate exist and contain data
before stopping support or preparing a replacement package.

Transport changes update the owned launch definition atomically. Conflicting
or unfamiliar jobs are not overwritten. Previous packages are retained until
removed explicitly.

## Installed files

| Path under the user's home directory | Purpose |
| --- | --- |
| `Library/Application Support/Mirra/current` | Rust CLI, service code, adapters and Python runtime |
| `Library/Application Support/Mirra/current/private` | SSH access and device certificate |
| `Library/Application Support/Mirra/current/config.json` | Installed profile |
| `Library/Application Support/Mirra/current/runtime` | Session and attempt state |
| `Library/Application Support/Mirra/logs` | Application and service diagnostics |
| `Library/Application Support/Mirra/service.json` | Current or last session pointer |
| `Library/Caches/Mirra` | Ownership and recovery records |
| `Library/LaunchAgents/local.mirra.agent.plist` | Login registration |

Package hashes and host compatibility are verified before startup. Apple's app
is used from `/System/Applications/iPhone Mirroring.app` and is not copied into
the package. Private profiles and installed service folders are not distributable
app packages.

## Diagnostic storage

Service diagnostics rotate at 2 MiB with one tail backup. Bursts can briefly
exceed the threshold between rotation checks. SSH stderr keeps a bounded memory
tail. App log files follow the [dated retention policy](App.md#logs).

After verified cleanup, support retains three completed backend attempts and
three completed native sessions, plus the active attempt and session. Live,
unfinished or unfamiliar directories are preserved. Installation backups are
not automatically pruned.

Temporary broker workspaces use a lease. They are removed after sharingd is
restored and the lease is unused. Cleanup verifies ownership and does not follow
substituted symlinks. Retention events appear in the service log; a deferred
result means the data was preserved because verification did not finish.

## Recovery

Launchd restarts a failed supervisor. Backend workers retry independently after
their children exit and the previous native registrations are restored. The
controller verifies process birth times, staged configuration and exclusive
ownership before recovering an abandoned job.

A failed observation does not authorize a replacement. Unresolved cleanup keeps
its recovery record and blocks package replacement until restoration finishes.
Updating stopped support first runs the existing recovery routines against its
installed runtime. The updater holds the backend session lock and checks children
recorded by pending sharing recovery before moving that runtime. It preserves
the package if a controller or guardian is still alive, the GUI domain cannot be
queried, or restoration cannot be verified. After recovery succeeds, it archives
the old package and installs the update using the saved bridge configuration.
Target Mirroring may still need a new Connect action after backend recovery.

## Python runtime

The service uses its own verified Python copy. Its launch command does not
depend on the app's current location, so moving or closing the app leaves
background support available. A missing or modified recorded runtime file
prevents startup.
