# App guide

Mirra opens in **Setup**. Use **Settings** and **Logs** to manage and inspect
background support.

## Setup

- **Connect to an Existing iPhone** pairs with a phone that already runs Mirra
  Bridge. Select Wi-Fi or USB. For Wi-Fi, enter the bridge phone's address. For
  USB, select it from the device list. Copy the pairing token from the phone’s
  **Settings → Mirra Bridge** and choose **Pair iPhone**. The default bridge
  port is 47820.
- **Set Up a New iPhone** installs Mirra Bridge on a separate jailbroken iPhone
  running iOS 15 or later, with OpenSSH and `ldid` installed. Choose Wi-Fi or
  USB and enter the SSH account and port. Compare the displayed SSH fingerprint
  with a trusted value before authorizing access. Enter the phone's password
  when prompted. **Prepare Connection** installs the bridge and prepares its certificate.

With either option, **Finish Setup** activates the verified bridge and enables
background support at login. Once support is ready, open Apple's iPhone
Mirroring directly from the Dock, Spotlight or Launchpad. **Connect** in Mirra
also opens Apple's app. An active Mirroring session closes when you switch
bridges. **Resume Setup** reopens a saved setup step. To restore a
`ready.json` profile with its access files, stop background support in
**Settings** and choose **Import…** in **Setup**.

For command-line setup, see [Bridge setup](Setup.md).

## Connect

| State | Action |
| --- | --- |
| No saved setup | Open Setup and choose how to connect your bridge. |
| Bridge ready | **Connect** checks bridge health and opens Apple's app. |
| Service stopped | **Connect** starts support and waits for readiness. |
| Support update available | **Update and Connect** reuses the saved bridge profile. |
| Bridge update available | **Update Bridge** installs the bundled service on the bridge iPhone. |
| Connecting or restoring | Wait for the active operation to finish. |
| Status unavailable | **Check Again** refreshes the observation. |

Keep the target iPhone locked and nearby with Wi-Fi and Bluetooth enabled, and
complete authentication in Apple’s window.

**Update Bridge** uses the saved SSH connection over Wi-Fi or USB and keeps the
phone’s pairing token, certificate, and saved Macs. The bridge service restarts
during the update. If this Mac paired by token only, update from a Mac with
verified SSH access to the bridge. An expired bridge certificate can be retried
separately with **Renew Now** after updating.

## Settings

- **Start Support** and **Stop Support** control background support. Closing
  Mirra leaves support running. Stopping retains login registration, which the
  [service CLI](Service.md) can remove.
- **Refresh Status** reads the service status again.
- **System**, **Light** and **Dark** set the appearance.
- **About** shows the app version.

## Logs

Mirra captures setup commands, SSH output, helper results, service activity, and
available iPhone Mirroring and decoder messages. Capture continues while the app
is open. Passwords and key and certificate contents are redacted.

**Pause** freezes the displayed entries. **Copy** copies them, including the
host observations collected at launch. **Verbose** includes routine framework
debug messages. **Open Log Folder** opens
`~/Library/Application Support/Mirra/logs` in Finder.

Mirra keeps seven days of dated logs. Each file rotates at 2 MiB with one backup.
Service and session diagnostics have separate
[retention rules](Service.md#diagnostic-storage). Review logs before sharing.
