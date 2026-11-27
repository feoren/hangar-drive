# Security Policy

Hangar Drive stores and syncs your files, so security reports are taken seriously.

## Reporting a vulnerability

Please **do not open a public issue.** Use GitHub's
[private vulnerability reporting](../../security/advisories/new) instead. Include the Hangar Drive
version, your operating system, steps to reproduce and the impact you expect.

You will get an initial response within a week. Once a fix is released, the advisory is published with
credit to you unless you prefer otherwise.

## Supported versions

Only the latest release receives security fixes.

## Installation per user

On Windows, Hangar Drive installs for the current user only, without administrator rights.
Everything it keeps belongs to that user: the program files, the index and the settings in
`%LOCALAPPDATA%\Hangar Drive`, and the device keys in that user's Windows Credential Manager
(local, not roaming). Anyone who can run programs or read files as that user can therefore
also change the installed app or use its keys; protect the user account itself (a password or
Windows Hello, BitLocker on a laptop). Uninstalling removes the device keys, the index and the
settings only when you tick "Delete app data and this PC's device keys" on the uninstaller's
confirmation page. Without the tick they stay, also when an upgrade or downgrade uninstalls the
old version first, so that the app carries on as the same device. Tick it, or reset the device
in the app, before you hand the PC or the Windows account to someone else. The synced files stay where they are either way.

## Scope

In scope, for example:

- reading, changing or deleting files outside the folders you chose
- file contents, names or credentials leaking into logs, config files or the network beyond what the
  settings describe
- the frontend reaching backend capabilities that were not explicitly granted
- bypassing the update signature check
- another local user, or a page in the app's window, reaching the device keys or the files of a
  user who installed Hangar Drive

The self-hosted sync server (`server/`) is in scope as well, for example:

- signing in without a device key, or using a session beyond what its scope allows
- reading, changing or deleting data of another account, or of a folder or device the session
  does not own
- making the server forget or delete versions a client cannot delete on its own
- keeping a server from serving other accounts without signing in (resource exhaustion that a
  single unauthenticated client or network can cause), or with one account's session beyond
  the limits `docs/self-hosting.md` describes

Out of scope:

- a misconfiguration by the operator, such as trusting a whole address range in
  `HANGAR_DRIVE_TRUSTED_PROXIES`, publishing the port without TLS, or leaving backups readable
- denial of service that needs more traffic than the host's own network can take
- what the operator of a server sees by design (object sizes, counts and times, never contents
  or names), and an operator deleting data on their own server
