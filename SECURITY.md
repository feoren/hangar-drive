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
Windows Hello, BitLocker on a laptop). Uninstalling removes the device keys and the index; the
synced files stay where they are.

## Scope

In scope, for example:

- reading, changing or deleting files outside the folders you chose
- file contents, names or credentials leaking into logs, config files or the network beyond what the
  settings describe
- the frontend reaching backend capabilities that were not explicitly granted
- bypassing the update signature check
- another local user, or a page in the app's window, reaching the device keys or the files of a
  user who installed Hangar Drive
