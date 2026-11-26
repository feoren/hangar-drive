---
title: UX concept of the desktop app
type: synthesis
tags: [ux, ui, onboarding, tray, conflicts, restore, devices, settings, accessibility, i18n, plurals, re-anchor]
sources: ["[[threat-model-and-crypto-design]]", "[[sync-prior-art-research]]", "[[recycle-bin-measurement]]"]
created: 2026-11-26
updated: 2026-11-26
---

# UX concept of the desktop app

The owner's requirement, verbatim: "Es muss 100% benutzerfreundlich werden, extrem einfach zu
bedienen." This page turns that into flows, screens, a tray state model and the complete UI copy
for version 1 of the desktop app. It builds on [[0001-foundation]] and on sections 2 and 4 of
[[threat-model-and-crypto-design]]. It is a concept: no code exists for any of it yet.

**Markers.** Every rule carries its origin:

- **[ADR]** follows from [[0001-foundation]] (section number given) or from the threat model.
  Changing it means changing the decision first.
- **[Design]** is a design decision of this concept. It can change without touching the ADR.
- **[Backend]** is a design decision that needs something from the sync core, the protocol or the
  server that the ADR does not name yet. These are collected under "Handover" at the end.

## 1. Principles

1. **Nothing to understand before it works.** [Design] A person who has never heard of
   encryption, servers or sync finishes the setup with one link, one code to keep and one click.
   Technical terms never appear in the interface (see the vocabulary in section 2).
2. **Invisible when everything is fine.** [Design] Like OneDrive, the app lives in the tray and in
   Explorer. The window is for looking, not for working. No notification ever says that something
   went well.
3. **Nothing is ever lost silently.** [ADR 3, 5] Conflicts keep both versions, a change beats a
   delete, a missing folder pauses, mass deletions ask, the server keeps every version for the
   retention window. The interface says so in plain words, because that promise is what lets
   people stop worrying.
4. **One question at a time, with a safe default.** [Design] A problem that needs a decision
   shows one sentence, one recommended button and at most one alternative. The recommended button
   is the one that loses nothing.
5. **Say what happened and what to do now.** [Design] Every problem text has exactly two parts:
   the situation in the person's words, then the next step. No error codes in the main text; they
   go into the diagnostic report.
6. **Calm over alarm.** [Design] Being offline on a laptop is normal and shown in grey, not as a
   problem. Red is reserved for "your data is at risk unless you act".
7. **Honest about limits.** [ADR Consequences] The app does not pretend to delete what only the
   operator can delete, and it says that synced files lie unencrypted on this computer.
8. **Everything reachable by keyboard and screen reader, at 640 × 420.** [Design] See section 12.
9. **The Hangar family look.** [Design] Tokens, dialog shape and settings layout come from the
   sister app (`src/styles.css` here, taken from there). No new colors, no new radii.

## 2. Vocabulary

The interface uses the left column only. Internal terms stay in code and docs.

| Users see (de / en) | Internal term | Note |
| --- | --- | --- |
| Ordner / folder | sync root, folder with key ring | [Design] |
| Gerät / device | device identity, device log entry | [Design] |
| Einladungslink / invite link | invite token plus server URL, server ID, optional SPKI pin | [Design]; the invite itself is [ADR 6] |
| Kopplungslink, Kopplungscode / pairing link, pairing code | pairing offer, pairing secret P | [Design]; offer [ADR 4] |
| Sicherheitsnummer / safety number | 30 digit safety number over the device key | [Design]; the term is the sister app's |
| Ordnernummer / folder number | folder safety number over the frontier | [ADR 4]; shown like the safety number (8.6, 8.7) |
| Servernummer / server number | server key number over the server's SPKI | [ADR 6]; shown like the safety number (8.3), only as a row of numbers to compare |
| Wiederherstellungscode / recovery code | recovery device secret | same term as the sister app |
| Wiederherstellungsblatt / recovery sheet | printed sheet with code, server address, server ID, account ID, genesis anchor, optional pin and the link `hangar-drive://recover#...` | [ADR 4]; version 2 (4.4) |
| Version, früherer Stand / version, earlier state | commit | [Design] |
| Papierkorb / trash | files dropped by retained commits | [ADR 5] |
| zwei Fassungen / two versions | conflict copy | [Design]; the word "Konflikt" appears only in the file name |
| dein Server, der Betreiber / your server, the operator | sync server, operator | [Design] |

Never shown: commit, head, epoch, key, encryption key, token, hash, frontier, chunk, manifest,
SPKI, sync root, protocol version. "Verschlüsselt" / "encrypted" appears exactly twice: in the
first setup step ("Nur deine Geräte können deine Dateien lesen") and in the "About" area.

## 3. Shell: tray, window, background

- **Background first.** [Design] The app starts with the OS sign-in, minimized to the tray.
  Autostart is on by default and can be switched off in the settings (section 11). The first start
  after installing opens the setup window.
- **Closing the window keeps it running.** [Design] The close button hides the window. The first
  time, a one-time notification says "Hangar Drive läuft im Infobereich weiter." Quitting is in the
  tray menu only. Quitting never asks, because nothing is lost: files are local and sync resumes on
  the next start.
- **Tray click.** [Design] A left click opens the main window (or brings it to the front). A
  right click opens the tray menu. Windows hides new tray icons in the overflow area; the end of the
  setup shows a one-line hint how to pin it. [Backend]
- **Explorer.** [Design] The default folder is added to the Explorer navigation pane and Quick
  Access, like OneDrive, so people find their files where they already look. [Backend]

> [!question] Unverified
> The navigation pane entry (a shell namespace extension registered per user) and pinning to
> Quick Access are assumed to work without a packaged app on Windows 10 1809 and later. Check
> before committing to it; without it, the folder is still reachable through the tray menu.

- **Window size.** [Design] Default 720 × 520, minimum 640 × 420, resizable, position and size
  remembered. One window only; every dialog is a modal inside it (the sister app's `Dialog`
  pattern with focus trap and Escape).

## 4. First start

### 4.1 Welcome

```text
+--------------------------------------------------------------+
|                                                              |
|                         [app mark]                           |
|                  Willkommen bei Hangar Drive                 |
|    Deine Dateien auf allen deinen Geräten, auf deinem        |
|    eigenen Server. Nur deine Geräte können sie lesen.        |
|                                                              |
|            [ Mit Einladungslink starten ]   (primary)        |
|            [ Ich nutze Hangar Drive schon auf                |
|              einem anderen Gerät ]          (secondary)      |
|                                                              |
|        Kein Gerät mehr da? Wiederherstellungsblatt nutzen    |
|                                                (link)       |
+--------------------------------------------------------------+
```

Three doors, because there are exactly three situations. [Design] The third is a quiet link: it
is rare, and it must not tempt first-time users.

### 4.2 New account: three steps

A step indicator "Schritt 1 von 3" sits above the title; the steps really are a sequence.
"Zurück" is available in steps 2 and 3 until the account exists (see 4.2.1). [Design]

#### Step 1: connect to the server

```text
+--------------------------------------------------------------+
| Schritt 1 von 3                                              |
| Mit deinem Server verbinden                                  |
| Füge den Einladungslink ein, den du vom Betreiber deines     |
| Servers bekommen hast.                                       |
|                                                              |
|  Einladungslink                                              |
|  [ https://drive.example.org/join#...            ] [Einfügen] |
|                                                              |
|  (after a valid link:)                                       |
|  ✓ drive.example.org                                         |
|    Name dieses Geräts  [ Arbeitslaptop                    ]  |
|                                                              |
|                                         [ Weiter ]           |
+--------------------------------------------------------------+
```

- **One link is enough.** [Design] The operator's invite is a single link of the form
  `https://<server>/join#<invite>`. It carries the server address, the server ID, the single-use
  invite [ADR 6] and, for self-signed setups, the SPKI pin [ADR 6]. Nobody types a URL.
- **Three ways in, all the same field.** [Design]
  1. Paste: the "Einfügen" button reads the clipboard only on that click (no silent clipboard
     reading). Pasting with Ctrl+V into the field works too. The shell hands over only a link or
     code of the app (security review L2); for anything else, as for an empty clipboard, the field
     says calmly, without error colour, "In der Zwischenablage ist kein Link von Hangar Drive."
  2. Click in a browser or mail: the server serves a small static page at `/join` with a button
     that opens `hangar-drive://join#<invite>`; the app receives it and fills the field. [Backend]
  3. QR code: the operator can show the same link as a QR code. A desktop rarely has a camera, so
     scanning is offered only when one exists ("Mit Kamera scannen"). [Design]
- **The invite stays in the fragment** after `#`, so it does not land in proxy or access logs.
  [Design, in the spirit of ADR 6]
- **Link formats.** [ADR 6, sync engine `links.rs`] The invite is
  `https://<server>[/<base>]/join#<token>[.<server ID>[.<pin>]]` or, from the `/join` page,
  `hangar-drive://join#<invite>@<server URL>`. Pairing is `hangar-drive://pair#<offer>`, the
  sheet `hangar-drive://recover#<sheet>`. Every link field of the app recognizes all of them by
  their shape (`src/domain/links.ts`); white space inside a link is removed while the person
  types or pastes (the caret stays after the same character), so it never reaches the backend,
  whose parsers refuse it: a link never contains any, and a copied or printed link often breaks
  over lines or is typed in groups of four. A link
  of another kind is named in words ("Das ist ein Kopplungslink von einem deiner Geräte.") with a
  button that opens its own door, the link filled in; it is never sent as the wrong kind. Links the
  OS hands to the app arrive as the event `openLink` and open the matching door the same way; on a
  device that is already set up they show "Dieses Gerät ist schon eingerichtet" (`link.notNeeded.*`),
  except a pairing link while the server identifies itself differently (8.3) or after this device
  was removed (8.8), which fills the field of that flow. Nothing is sent before the person presses
  the button of the flow. [Design]
- **A pinned invite (N3).** When the invite carries a pin, the server has no certificate from a
  public authority and the device will trust the key the link names. Below "Verbunden mit {host}"
  a calm notice in the banner's warn tone says so and advises to accept the link only straight from
  the operator (`setup.connect.pinnedTitle`, `setup.connect.pinned`). It asks for no extra click:
  the operator of a self-hosted server is usually the person or someone they know, and the advice
  is what protects. [Design]
- **Hosts in punycode (N2).** Every host the window shows comes from the backend in the ASCII
  form the client connects to, so an internationalized name appears as `xn--...` and letters
  that look alike cannot hide another server. [Design, Backend]
- **Validation happens while typing**, not on "Weiter". A recognised link shows the server's host
  name with a check mark. The app contacts the server at once to check the invite, so an expired
  or used link is reported in step 1, not after the recovery code. [Design]
- **Device name** is prefilled with the computer name and can be changed here or later under
  Devices. [Design]
- **What "Weiter" does:** it checks the invite and creates the device identity locally. The
  invite is redeemed only after step 2, because the recovery device must be in the log from the
  start (4.2.1). [Backend]

#### Step 2: recovery code

```text
+--------------------------------------------------------------+
| Schritt 2 von 3                                              |
| Dein Wiederherstellungscode                                  |
| Wenn du alle Geräte verlierst, holt dieser Code deine        |
| Dateien zurück. Es gibt keinen anderen Weg, auch nicht über  |
| den Betreiber.                                               |
|                                                              |
|   +------------------------------------------------------+   |
|   |  D7KQ  M2XP  9H4T  RW8C  ZB3N  F6JA  Q1VE  K5SY       |   |
|   +------------------------------------------------------+   |
|                                                              |
|   [ Drucken ]  [ Als Datei speichern ]  [ Kopieren ]         |
|                                                              |
|   Bewahre ihn auf wie einen Haustürschlüssel: Wer ihn hat,   |
|   kann deine Dateien lesen.                                  |
|                                                              |
|                                   [ Ich habe ihn gesichert ] |
+--------------------------------------------------------------+
```

then, after "Ich habe ihn gesichert":

```text
| Kurz prüfen                                                  |
| Tippe die 5. Gruppe deines Codes ab.                         |
|   Gruppe 5  [ ____ ]                                         |
|                                         [ Bestätigen ]       |
|                         Code noch mal ansehen (link)         |
```

- **Format.** [ADR 4] 128 random bits, Crockford base32 with checksum, the sister app's structure:
  32 characters in 8 groups of 4. On screen the groups are separated by spaces and the code is set
  in the monospace token, large (20 px), selectable. [Design]
- **Print** produces the recovery sheet, version 2 [ADR 4, threat model 2.3]: the code, in the
  clear the server address, server ID, account ID, genesis anchor, the pin when there is one, the
  link `hangar-drive://recover#...`, the date, the device that created it, and four plain
  sentences (4.4, "The sheet, version 2"). [Design] The QR code on the sheet holds the link only,
  never the code, which is always typed. [ADR 4]
- **Save as file** writes a short text file with the same content. The save dialog proposes the
  Documents folder; choosing a place inside a synced folder is refused with a reason
  ("recovery.savedInSync"), because the code must not travel to the server next to the data it
  opens. [Design, same reasoning as the sister app's repository check]
- **Copy** puts the code on the clipboard and clears it after one minute, with that said in the
  feedback text. [Design, sister app pattern]
- **Typing one group back** [ADR 4]: the group is chosen at random, never group 1 (people copy
  the first group from memory). Input ignores case and spaces, and maps `O` to `0`, `I` and `L`
  to `1` (Crockford). A wrong group says so without revealing the right one; after it, a link
  shows the code again. [Design]
- **This step cannot be skipped.** [Design] The owner asked for "extremely simple", but a skipped
  code turns a lost laptop into lost data with no way back, which is the opposite of simple. The
  step costs about 30 seconds and is the only place where the app asks for attention.
- **Code prefix.** [Design] Drive codes should start with a fixed letter (proposal: `D`, through
  the version byte), so the recovery screen can say "Das ist ein Code für ... , hier gehört der
  Code für Hangar Drive hin" when someone types a sister app code. [Backend]

#### Step 3: choose the folder

```text
+--------------------------------------------------------------+
| Schritt 3 von 3                                              |
| Wo sollen deine Dateien liegen?                              |
|                                                              |
|   [folder]  Hangar Drive                                     |
|             %USERPROFILE%\Hangar Drive          [ Ändern ]   |
|                                                              |
|   Alles, was du in diesen Ordner legst, ist auch auf deinen  |
|   anderen Geräten. Weitere Ordner kannst du später           |
|   hinzufügen.                                                |
|                                                              |
|                                    [ Fertig ]                |
+--------------------------------------------------------------+
```

- **Default.** [Design] `%USERPROFILE%\Hangar Drive`, like OneDrive. The full path is shown, so
  nobody wonders where the files went.
- **"Ändern"** opens the OS folder picker. Refused with a reason, live: a network drive
  [ADR 2], a drive root, a system folder (Windows, Program Files, the user profile itself), a
  folder inside or around another synced folder, the app's own data folder. [Design]
- **An existing, non-empty folder** is accepted; the line below changes to "Der Ordner enthält
  schon {count} Dateien, die hochgeladen werden." (`folder.setup.existing`, plural forms per
  section 13). Nothing is on the server yet, so nothing can clash. [Design] A non-empty folder
  for a folder that already has files on the server is a different case: section 6.5.
- **"Fertig"** creates the folder, writes the root marker [ADR 5], shows a short done screen
  ("Alles bereit") with "Ordner öffnen" (primary) and the tray pin hint, then closes into the tray
  after the person clicks or after leaving the window. [Design]

#### 4.2.1 Where the account comes into being

Steps 1 and 2 must not leave a half account if the person closes the window in step 2. [Backend]
Proposal: the invite is checked in step 1 but redeemed only when the group in step 2 is
confirmed, together with the first device entry and the recovery device. Until then nothing
exists on the server, and closing the window means starting step 1 again with the same link.

### 4.3 Additional device: two steps

Chosen with "Ich nutze Hangar Drive schon auf einem anderen Gerät". There is no recovery code
step, because the account already has one. [Design]

**Step 1: pair.**

```text
+--------------------------------------------------------------+
| Schritt 1 von 2                                              |
| Mit deinem anderen Gerät koppeln                             |
| Öffne Hangar Drive auf dem anderen Gerät und wähle dort      |
| Geräte > Gerät hinzufügen. Füge dann hier den Kopplungslink  |
| ein.                                                         |
|                                                              |
|  Kopplungslink  [ hangar-drive://pair#...      ] [Einfügen]  |
|                                                              |
|  [ Mit Kamera scannen ]  (only with a camera)                |
|  Kein Kopieren möglich? Code abtippen (link)                 |
|                                                              |
|  Name dieses Geräts  [ Arbeitslaptop                      ]  |
|  So erkennst du es später in der Geräteliste.                |
+--------------------------------------------------------------+
```

- **Name of this device.** [Design, security review N5] The same field as in 4.2, filled with the
  computer's name. It goes with the pairing (`startPairing(input, deviceName)`, trimmed), so the
  other device asks "„{device}“ möchte dazukommen." with the name the person chose. A blank name is
  refused at the field before anything is sent; the backend's own refusal is shown there too.
  A link the OS hands over skips this form and uses the computer's name.

- **Link or QR.** [ADR 4] The pairing offer (server address, optional pin, server ID, account ID,
  device ID, account log head, 128 bit secret, expiry) is one link, also shown as a QR code. On a
  desktop the realistic paths are copying it through anything the person already uses between
  their computers (a message to themselves, a password manager, a USB stick) or scanning with a
  webcam. [Design]
- **Typing path.** [ADR 4: "the person types the full-entropy code or compares safety numbers"]
  Two fields: the server address (as shown on the old device) and the pairing code (26
  characters, shown in groups). Without the log head from the offer, the new device cannot anchor
  the account log, so this path always requires the safety number comparison on both sides.
  [ADR 4] No short code: [ADR 4] forbids short codes until there is a PAKE.
- **Server question before sending (N2).** [Design, security review N2] A pasted, scanned or
  opened pairing link is first read offline (`inspectLink`). The window then shows "Mit diesem
  Server verbinden?" with the server's host in punycode and the account ID in groups of four,
  says where the other device shows both (`pair.check.body`; the offer screen of section 5 now
  names "Server {host}, Konto {account}"), and adds the calm pin notice when the offer pins the
  server. "Zurück" has the focus; "Verbinden" holds back clicks for 1 s like every confirm button
  of a comparison. Only "Verbinden" sends the link. The typed path needs no question: the person
  typed the server.
- **Waiting, link or QR.** [ADR 4, Design] The offer already carries the secret and the account
  log head, so the person only has to approve on the other device. The new device shows
  "Bestätige jetzt auf deinem anderen Gerät." (`pair.new.waitingLink`) and a collapsed
  "Zahlen anzeigen" (`pair.numbers.show`) with its safety number, for people who want to compare
  anyway.
- **Waiting, typed code.** [ADR 4] The new device shows "Bestätige jetzt auf deinem anderen
  Gerät. Dort steht dieselbe Zahlenreihe:" (`pair.new.waiting`) with its safety number open, because
  on this path the comparison is required (section 5).

**After joining: "Das sind deine Geräte?" (N2).** [Design, security review N2] Before any folder
is chosen, the new device lists the account's devices (`listDevices`), this one marked "Dieses
Gerät", with "Kennst du die Geräte nicht, brich ab: Dann wird es wieder getrennt, bevor Dateien
übertragen werden." "Ja, das sind meine" goes on to step 2; "Nein, abbrechen" disconnects this
device (`disconnectThisDevice`) and returns to step 1 with "Abgebrochen. Dieses Gerät ist wieder
getrennt, es wurden keine Dateien übertragen." A link that leads to a stranger's account shows
strangers here, before anything of this device reaches it.

**Step 2: choose folders.**

```text
| Schritt 2 von 2                                              |
| Welche Ordner sollen auf dieses Gerät?                       |
|   [x] Hangar Drive      12,4 GB   %USERPROFILE%\Hangar Drive  |
|   [x] Fotos             48,0 GB   %USERPROFILE%\Fotos         |
|   Auf diesem Computer sind 120 GB frei.                      |
|                                    [ Fertig ]                |
```

- All folders are checked by default, each with a proposed place in the user profile (same name)
  that "Ändern" in the row menu can change. [Design] Sizes are approximate (padded sizes from the
  server are close enough for a space check). [Backend]
- If the checked folders do not fit, the free space line turns into a warning and "Fertig" stays
  available: downloads simply stop when the disk is full (section 8.5). [Design]
- If a proposed or chosen place already holds files, "Fertig" first shows the merge question of
  section 6.5 for that folder. [Design]

### 4.4 Recovery with the sheet

Chosen with "Kein Gerät mehr da?". [ADR 4, threat model 2.3]

1. **Enter the sheet.** [ADR 4 "Sheet", open point A] The person pastes the sheet's link
   `hangar-drive://recover#...` (from the saved file or a password manager) or scans its QR code,
   and types the recovery code (8 groups of 4, one field that accepts the whole code pasted, spaces
   and dashes ignored). The link carries the server address, the server ID, the account ID, the
   genesis anchor and, for a self-signed server, the pin; the code is never part of it and is always
   typed. **The account ID is not looked up by the server and not typed separately: it comes with
   the link.** (The first version of this concept proposed a lookup by the recovery device's key;
   the ADR decided against it, because the sheet is the only place the account is named and the
   anchor binds the recovery to that account's log.) Once the link is read offline
   (`inspectLink`), the field says "Gefunden: {host}" and "Konto {account}" in groups of four, so
   the person can compare with the paper, and the device name appears, prefilled. Without a camera
   and with only the paper, the link is typed; white space is ignored, and the printed sheet sets
   the link in groups for that. [Backend: layout of the printed link] "Weiter" calls
   `recoverAccount(sheet, code, name)`.
2. **Clean up**, one screen: "Diese Geräte gehören noch zu deinem Konto. Entferne die, die du
   nicht mehr hast." All old devices are listed and checked. [ADR 4: remove the lost devices and
   the used recovery device]
3. **New recovery code**, the same screen as setup step 2: the used code stops working. [ADR 4]
4. **Choose folders**, as in 4.3 step 2.

Four screens: the name moved onto the first one, where it appears only after the link is read,
as in 4.2 step 1. Every screen is still one decision. [Design]

**The sheet, version 2.** [ADR 4, Design] Print and "Als Datei speichern" lay out the same
document, worded by the window in the UI language (`sheet.*`, `RecoverySheetDocument`): the
code, the server address, server ID, account ID, the account's check value (genesis anchor), the
server's check value (pin, only when there is one), the link to paste, the date and the device
that made it, then four plain sentences (what the code does, that it is full access together with
the server, that without it and without a device the data is gone, and how a recovery goes). The
printed sheet carries a QR code of the link, never of the code. On screen, the code step keeps the
code in front and folds the rest under "Was noch auf dem Blatt steht".

## 5. Adding a device, seen from the existing device

Devices > "Gerät hinzufügen":

```text
+--------------------------------------------------------------+
| Neues Gerät hinzufügen                                       |
| 1. Installiere Hangar Drive auf dem neuen Gerät.             |
| 2. Wähle dort „Ich nutze Hangar Drive schon auf einem        |
|    anderen Gerät“.                                           |
| 3. Scanne diesen Code oder füge den Link dort ein.           |
|                                                              |
|      +-----------+                                           |
|      |  QR CODE  |     [ Link kopieren ]                     |
|      +-----------+     (an image of the backend's SVG)       |
|                                                              |
|   Gültig bis 14:42, nur für ein Gerät.                       |
|   Kein Kopieren möglich? Code zum Abtippen zeigen (link)     |
|                                              [ Abbrechen ]   |
+--------------------------------------------------------------+
```

- **Expiry** [ADR 4: single use, 10 minutes] is a fixed time, not a ticking countdown: a running
  timer creates pressure for no benefit. After expiry the QR is replaced by "Dieser Code ist
  abgelaufen" and "Neuen Code erzeugen". [Design]
- **Copying the link** clears the clipboard after one minute, as for the recovery code. [Design]
- **Confirmation** [ADR 4, threat model 2.2 step 2]: when the new device has answered, the dialog
  changes. Its shape depends on how the new device got the offer.

  **Link or QR (the usual path):** one question, two buttons. [Design]

```text
| „Arbeitslaptop“ möchte dazukommen.                           |
|                                                              |
|   > Zahlen vergleichen (collapsed)                           |
|                                                              |
|                       [ Ablehnen ]   [ Hinzufügen ]          |
```

  **Typed code:** the numbers are shown and cannot be collapsed. [ADR 4]

```text
| „Arbeitslaptop“ möchte dazukommen.                           |
| Danach fragt dein System noch einmal nach und zeigt diese    |
| Zahlenreihe. Sag nur Ja, wenn das neue Gerät dieselbe zeigt. |
|                                                              |
|      48213  90577  12846                                     |
|      66031  27419  85502                                     |
|                                                              |
|                       [ Ablehnen ]   [ Hinzufügen … ]        |
```

- **The question itself is native.** [security review L2, 2026-11-26] "Hinzufügen …" leads to
  the operating system's own dialog, which the shell shows with the device's name, the sentence
  `pair.confirm.body` and the safety number, and the buttons "Ja, gleiche Zahlen, hinzufügen" and
  "Nein, abbrechen". A page that was taken over cannot click it. The window does not ask the same
  question first: two identical questions in a row teach people to click through both. The
  window's step only shows who wants to join (`pair.request.body` on both paths) and offers
  "Ablehnen", which declines at once without the native dialog. "Nein" in the native dialog
  declines too and shows the mismatch text below; it is not an error.

- **Why the comparison is optional on the link path.** [ADR 4] The link or QR code carries the
  128 bit secret and the account log head, so only the device that received it can answer. The
  numbers add nothing a person must check there; asking for them anyway teaches people to tap
  "same" without looking, which is exactly the habit the typed path cannot afford. The collapsed
  "Zahlen vergleichen" (`pair.numbers.compare`) shows the same rows as the typed path, with the
  sentence `pair.confirm.body`.
- **The confirm button waits a moment on both paths.** [ADR 6, threat model R8] "Hinzufügen …"
  takes no click for 1 s after the dialog appears or changes
  (the sister app's arm delay for number checks), so a click meant for what was there before
  cannot add a device. The button looks disabled during that second and its accessible name stays
  the same. "Ablehnen" works at once.
- **Plain language for the safety number.** [Design] The word "Sicherheitsnummer" is the label;
  the sentence is about what to do: compare two rows of numbers. Six groups of five digits, the
  same layout on both screens, so the eye can compare group by group. The screen reader reads the
  groups one by one ("Gruppe 1: 4 8 2 1 3").
- **Declined or mismatch** ("Ablehnen", "Nein"): "Dann füge das Gerät nicht hinzu. Starte auf dem
  neuen Gerät noch mal von vorn. Passiert das wieder, sprich mit dem Betreiber deines Servers."
  No talk of attackers. [Design]
- **After confirming**, both devices show a short success line; the existing device returns to
  the device list, where the new device appears at the top. [Design]

## 6. Everyday

### 6.1 Tray state model

The tray shows one state for the whole app, the most urgent across all folders. [Design]

| Priority | State | Icon shape (never color alone) | Tooltip (de) | Entered when | Left when |
| --- | --- | --- | --- | --- | --- |
| 1 | **Braucht dich** (problem) | cloud with exclamation mark, error color | Hangar Drive: Braucht deine Hilfe | a decision is pending (mass deletion), a folder is stopped for safety (missing folder, older state, suspected attack), this device was removed, the server refuses this device or needs an update, the disk or the server storage is full | the cause is gone or decided |
| 2 | **Angehalten** (paused) | cloud with two bars | Hangar Drive: Angehalten bis {time} | the person paused | the pause ends or "Fortsetzen" |
| 3 | **Offline** | cloud outline with a slash, muted | Hangar Drive: Offline. Änderungen werden später synchronisiert. | no network, or the server has not answered for 2 minutes | the server answers |
| 4 | **Synchronisiert** (syncing) | cloud with two arrows | Hangar Drive: {count} Dateien werden synchronisiert (`tray.state.syncing`, one and other form) | there is work for more than 2 s | no work for 3 s |
| 5 | **Aktuell** (up to date) | cloud with check mark | Hangar Drive: Alles aktuell, or "Alles andere ist aktuell" while files wait (below) | nothing else applies | |
| | **Einrichtung offen** | cloud outline | Hangar Drive: Einrichtung noch nicht fertig | setup not finished | setup done |

- **Waiting files are not work.** [Design] Files held back by a metered network or by the
  server's daily upload budget (8.4) do not count for state 4: the icon would otherwise show
  arrows for up to a day while nothing moves. The state follows the table without them, and the
  status shows one muted second line that says why they wait (`tray.metered`, `budget.line`).
  When nothing else is pending, the sentence is "Alles andere ist aktuell"
  (`tray.state.restUpToDate`), so the tray never claims "Alles aktuell" while files wait. The
  tooltip carries both lines.

- **Five, not four states.** [Design] The brief names four. Offline is split from "problem" on
  purpose: a laptop on a train is offline every day, and an icon that cries for help every day
  teaches people to ignore it. A server that stays unreachable for 24 hours is promoted to
  "Braucht dich" with its own text (section 8.3).
- **No animation.** [Design] The syncing icon is static. A spinning tray icon is seen all day and
  flickers in screenshots and screen recordings; the arrows say enough.
- **Hysteresis** (2 s in, 3 s out) keeps the icon from blinking when small files change. [Design]
- **Icon set:** a light and a dark taskbar variant and a high contrast variant, each at 16, 20,
  24 and 32 px. [Design]

### 6.2 Tray menu

```text
  Alles aktuell                         (status line, not clickable)
  Zuletzt: Bericht.docx, vor 2 Min.     (muted, not clickable)
  ----------------------------------
  Ordner öffnen                         (default item, bold)
  Hangar Drive öffnen
  ----------------------------------
  Pausieren                         >   Für 1 Stunde
                                        Bis morgen
                                        Bis ich fortsetze
  ----------------------------------
  Beenden
```

- When there is a problem, a first item "Problem ansehen" appears above "Ordner öffnen" and
  becomes the default. [Design]
- When paused, "Pausieren" turns into "Fortsetzen". [Design]
- **"Ordner öffnen"** opens the default folder; with several folders it is a submenu with one
  entry per folder. [Design]
- **Pause durations** auto-resume, so nobody forgets a pause for a week. "Bis morgen" means 06:00
  local time. [Design]
- Nothing else: no settings, no devices, no restore in the tray. Those live in the window.

### 6.3 Main window

```text
+------------------------------------------------------------------+
| Hangar Drive                            [Geräte] [Einstellungen] |
+------------------------------------------------------------------+
|  (check) Alles aktuell                                           |
|          Zuletzt synchronisiert um 14:31                         |
|                                                                  |
|  (banner area, only when there is something to decide)           |
|                                                                  |
|  Ordner                                                          |
|  [folder] Hangar Drive    %USERPROFILE%\Hangar Drive   Aktuell [...] |
|  [folder] Fotos           D:\Fotos         120 Dateien hoch... [...] |
|  + Ordner hinzufügen                                             |
|                                                                  |
|  Letzte Aktivitäten                                              |
|  Bericht.docx        Hangar Drive   geändert          vor 2 Min. |
|  Urlaub 014.jpg      Fotos          von Laptop        vor 1 Std. |
|  Notizen.txt         Hangar Drive   gelöscht          gestern    |
|                                                                  |
|  {used} von {quota} auf deinem Server belegt  (only above 80 %)  |
+------------------------------------------------------------------+
```

- **Status first.** [Design] One sentence at the top, the same as the tray tooltip, with one
  muted line below (time of the last sync, bytes left, or the pause end).
- **Banner area.** [Design] At most one banner at a time, the most urgent; further problems are
  counted on it ("Noch 2 weitere Hinweise"). A banner has a title, one sentence and one or two
  buttons. Banners are the only place where problems appear in the window, so the person never
  has to search.
- **Folder rows.** [Design] Name, full path (muted, truncated in the middle, full path as tooltip
  and accessible name), status in words, and a row menu:
  - Im Explorer öffnen (also on double click and Enter)
  - Frühere Versionen
  - Papierkorb
  - Pausieren / Fortsetzen (this folder only)
  - Ordnernummer anzeigen (for comparing with another device, 8.6 and 8.7)
  - Auf diesem Gerät nicht mehr synchronisieren
- **"Ordner hinzufügen"** offers the folder picker with the rules of setup step 3, or, if the
  account has folders that are not on this device, first a list of those ("Auf deinen anderen
  Geräten gibt es noch: Fotos"). [Design] A new folder that already holds files simply uploads
  them, as in setup step 3. Bringing an existing account folder to a place that already holds
  files asks first (6.5).
- **"Nicht mehr synchronisieren"** keeps the local files and everything on the server and says
  so in the confirmation. [Design]
- **Deleting a folder everywhere** [ADR 5: a retired folder can be brought back within the
  window] is the last row menu item, below a separator: "Auf allen Geräten löschen". The question
  is the operating system's own dialog, which the shell shows with the folder's name
  (`folder.delete.title`, "Überall löschen" or "Abbrechen"; security review L2); the window asks
  no question of its own before it, so the person answers once. "Abbrechen" there changes nothing
  and shows nothing. After a yes, a line below the folders says
  "„{folder}“ ist gelöscht." followed by `folder.delete.body` (the folder disappears from all
  devices and can be brought back for {days} days). Deleted folders appear in "Ordner hinzufügen"
  under "Gelöschte Ordner" with "Zurückholen" until the window has passed. [Design]
- **Activity list.** [Design] The last 50 events of this device, newest first: file name, folder,
  what happened (geändert, neu, gelöscht, umbenannt, von {device}, wiederhergestellt, zwei
  Fassungen), relative time. Many events of one run are grouped ("Fotos: 120 neue Dateien").
  Enter or double click shows the file in Explorer; the row menu has "Frühere Versionen".
- **Storage line** only above 80 % of the quota, because a number that is always there is noise.
  [Design, needs quota from the server: Backend]
- **Empty states.** [Design] No folder: "Noch kein Ordner. Füge einen hinzu, dann ist er auf allen
  deinen Geräten." with "Ordner hinzufügen". No activity yet: "Hier erscheint, was sich in deinen
  Ordnern ändert."

### 6.4 Notifications

OS notifications only for these, each at most once per cause: [Design]

| Cause | Why it may interrupt |
| --- | --- |
| Many deletions waiting for a decision | sync of deletions stops until answered |
| A folder stopped for safety (missing folder, older state) | the person may not notice for days otherwise |
| Suspected attack (anomaly pin) | [ADR 5] all devices are told |
| A device was added or removed | [ADR Consequences] removal notifications limit a lock out |
| Files with two versions | batched, at most one notification per 10 minutes |
| Storage full (server or disk) | changes stop going out |
| First close of the window | one time, explains that the app keeps running |

Never: "sync finished", "file uploaded", "back online". Clicking a notification opens the window
with the matching banner focused.

### 6.5 The chosen folder is not empty

- **Trigger.** [Design] A folder of the account comes to this device (4.3 step 2, 4.4 step 5, or
  "Ordner hinzufügen" with a folder from the other devices), and the place chosen for it already
  holds files. Entries the built-in ignore list skips [ADR 7] are not counted.
- **What happens.** [ADR 3 "Joining a non-empty local folder"] The local files are merged with
  the folder on the server, by the same rules as every other merge, with an empty base: a file
  with the same name and the same content is taken once, a file that exists only here is
  uploaded, and a file whose content differs keeps the server version under its name while the
  local one becomes a conflict copy (7.1). Nothing is deleted on either side.
- **The question**, once per folder, before anything is uploaded:

```text
| In diesem Ordner liegen schon 214 Dateien                    |
| Sie kommen zu „Fotos“ dazu. Ist eine Datei anders als auf    |
| deinen anderen Geräten, bleiben beide Fassungen erhalten.    |
|                                                              |
|   %USERPROFILE%\Fotos                                        |
|                                                              |
|         [ Anderen Ordner wählen ]   [ Zusammenführen ]       |
```

- **Default.** [Design] "Zusammenführen" is the primary button: it loses nothing, and a person
  who picked that place usually meant it. "Anderen Ordner wählen" opens the picker again with the
  same rules. Escape goes back to the screen before, nothing is uploaded.
- **Count first.** [Design] The number of local files is the one fact that tells a person whether
  they picked the right place ("214 Dateien" in an empty-looking `Fotos` is a sign of the wrong
  folder). Until the count is known the line says "Dateien werden gezählt …" and
  "Zusammenführen" waits.

## 7. Conflicts and names

### 7.1 Two versions of one file

- **Rule.** [ADR 3] Both versions are kept. The version that reached the server first keeps the
  name; the local version of the merging device becomes `<name> (conflict <device> <date>).<ext>`.
  A change beats a delete. The date is only a label, so the interface never calls one version
  "newer" or "older"; it names device and time for both.
- **No dialog, no decision required.** [Design] "Beide behalten" is not a button, it is what
  already happened. The person gets one batched notification and an activity entry:
  "Bericht.docx wurde auf zwei Geräten geändert. Beide Fassungen sind da."
- **Tidying up is optional.** [Design] The main window shows a quiet banner "2 Dateien gibt es in
  zwei Fassungen" with "Ansehen". The list shows per file both versions with device, time and
  size, and three actions: "Beide öffnen", "Diese behalten" (per version) and "Beide behalten"
  (default, closes the entry). The banner is informational: it does not raise the tray to
  "Braucht dich".
- **Grouping by the conflict link, never by the name.** [ADR 3 `conflict_of`] A list entry is one
  original plus every copy whose `conflict_of` names it. The app never reads `(Konflikt ...)` out
  of a name: a file the person happens to call that is a normal file, and a copy written by a
  device in another language is grouped just the same. A copy whose original is no longer in the
  folder (dangling link) is not listed; it is an ordinary file.
- **"Diese behalten"** [ADR 3] writes the chosen content into the original: it keeps the
  original's name and place, and the copy disappears. So the file is where the person and their
  programs expect it, whichever version they chose. The version not chosen stays restorable for
  {days} days through "Frühere Versionen" of the folder: as an earlier state of the original, or
  as the removed copy, which the trash (9.3) also lists like any file that is gone. The feedback
  line says so (`conflict.keptThis`) and offers "Rückgängig".
- **"Beide behalten"** [ADR 3] ends the pairing for all devices: the copy stays as a normal file
  under its name and the entry leaves the list everywhere.
- **Renaming or moving the copy** [ADR 3] also ends the pairing. The person has decided what the
  file is, so the entry leaves the list without a question. Editing either file, or renaming or
  moving the original, keeps the entry.
- **Change beats delete.** [ADR 3] When a deleted file comes back because another device changed
  it, the activity says "Notizen.txt ist wieder da, weil es auf Laptop geändert wurde."
- **Case-only collisions** [ADR 7] are conflicts too and appear in the same list, with the
  sentence "Zwei Dateien unterscheiden sich nur in Groß- und Kleinschreibung. Windows kann sie
  nicht nebeneinander speichern."

- **Language of the copy's name.** The merging device writes the word in its UI language
  (`conflict.fileWord`), English as the fallback. Decided below ("Decisions on the open
  questions", item 1) and recorded in [[0001-foundation]] section 3.

### 7.2 Names that do not work on Windows

- **Rule.** [ADR 7] Such files are marked "kann auf diesem Gerät nicht synchronisiert werden" and
  never renamed silently.
- **Presentation.** [Design] A banner "1 Datei kann auf diesem Gerät nicht gespeichert werden"
  with "Ansehen". Per file: the name, the reason in words, and the device it came from.

| Reason | Text (de) |
| --- | --- |
| forbidden character | Der Name enthält „{char}“. Das erlaubt Windows nicht. |
| reserved name | „{name}“ ist unter Windows ein reservierter Name. |
| trailing dot or space | Der Name endet mit einem Punkt oder Leerzeichen. Das erlaubt Windows nicht. |
| control character | Der Name enthält ein unsichtbares Steuerzeichen. |

- **One click to fix.** [Design] "Umbenennen" opens a field prefilled with a suggestion (the
  character replaced by a space or removed, the reserved name with `_` appended) and validates
  while typing. The rename is a normal rename for all devices, done because the person asked,
  so it does not contradict "never silently". "Ignorieren" hides the entry on this device; the
  file stays everywhere else.
- **Tray state.** These entries do not raise "Braucht dich": nothing is lost, the file is safe on
  the server and on the other device. [Design]
- **Other entries this device cannot create** [ADR 7], for example an entry that exists locally
  as a symbolic link under the same name, appear in the same list with
  `names.cannotCreate` and only "Ignorieren".
- **What is never synced** [ADR 7: links, junctions, system files, the built-in ignore list] is
  not a problem and raises no banner. The folder details show one quiet line, "{count} Einträge
  werden nicht synchronisiert", which opens the list with the reason per entry, so nobody wonders
  why a shortcut is missing on the other computer. [Design]

## 8. Problems

Every problem below has: trigger, where it shows, the copy keys (section 13), the actions, and
which action is the default (focused, primary style).

### 8.1 Many deletions at once

- **Trigger.** [ADR 5] More than 100 local deletions in one run would be sent to the server
  (Nextcloud's default; OneDrive asks above 200, [[sync-prior-art-research]]).
- **Behavior.** [ADR 5, Design] Only the deletions wait; every other change keeps syncing. The
  tray goes to "Braucht dich", a notification appears, and the window shows a dialog (not only a
  banner, because a decision is required).

```text
+--------------------------------------------------------------+
| 342 Dateien gelöscht                                         |
| In „Fotos“ wurden 342 Dateien gelöscht. Sollen sie auch auf  |
| deinen anderen Geräten verschwinden?                         |
|                                                              |
|   Urlaub 001.jpg, Urlaub 002.jpg, Urlaub 003.jpg             |
|   und 339 weitere   Liste ansehen (link)                     |
|                                                              |
|   Im Papierkorb bleiben sie {days} Tage lang erhalten.       |
|                                                              |
|          [ Wiederherstellen ]   [ Ja, löschen ]              |
+--------------------------------------------------------------+
```

- **Default.** [Design] "Wiederherstellen" has the initial focus because it loses nothing; it
  brings the files back into the folder from the last synced state. "Ja, löschen" is the danger
  style. Escape closes the dialog without deciding; the banner stays.
- **No "do not ask again".** [Design] The threshold is the whole point of the guard.
- **Incoming deletions** from other devices do not ask. Files deleted locally because another
  device deleted them go to the Windows recycle bin, not into nothing. The activity shows
  "Fotos: 342 Dateien auf Laptop gelöscht" with "Wiederherstellen". [Design]

- **Where they go.** [Backend, measured on Windows, [[recycle-bin-measurement]]] Windows:
  `IFileOperation` with `FOFX_RECYCLEONDELETE`, the plain path (the shell refuses `\\?\` paths).
  Where the shell would delete for good instead (a path beyond `MAX_PATH`, a `subst` drive, a
  drive without a recycle bin), the file goes to the folder's quarantine
  `.hangar-drive/trash/<item ID>/` for 30 days. macOS: the Finder trash
  (`trashItemAtURL`); Linux: the XDG trash; both untested so far.

### 8.2 Missing folder

- **Trigger.** [ADR 5] The root marker file is missing (folder deleted, renamed, moved, external
  drive unplugged).
- **Behavior.** The folder pauses; nothing is deleted anywhere. [ADR 5] When the marker shows up
  again (drive plugged back in), the folder resumes by itself and the banner disappears. [Design]
- **Banner.** "„Fotos“ ist nicht mehr da" / "Hangar Drive hat den Ordner angehalten. Auf dem
  Server und auf deinen anderen Geräten ist nichts gelöscht."
- **Actions.** "Ordner suchen" (default; picks the new place if it was moved or renamed and
  checks the marker), "Neu herunterladen" (to the old place), and in the row menu "Auf diesem
  Gerät nicht mehr synchronisieren".

### 8.3 Server not reachable

Three cases, three tones: [Design]

| Case | Detection | Tray | Text |
| --- | --- | --- | --- |
| no network | OS reports offline | Offline | "Offline. Deine Dateien sind hier, Änderungen gehen später raus." |
| server silent | no answer for 2 minutes | Offline | "Dein Server antwortet gerade nicht. Hangar Drive versucht es weiter." with "Jetzt versuchen" |
| server silent for 24 hours | as above | Braucht dich | "Dein Server antwortet seit gestern nicht. Sag dem Betreiber Bescheid." with "Fehlerbericht kopieren" |
| certificate does not match | TLS or pin failure | Braucht dich | "Dein Server weist sich anders aus als sonst. Zu deiner Sicherheit verbindet Hangar Drive nicht. Frag den Betreiber, ob er etwas geändert hat." with the two ways below |

- There is no button to accept an unknown certificate. [ADR 6]
- Local work continues in every case; the text says so, because that is the main worry. [Design]

#### The server identifies itself differently

[ADR 6 "Pin rotation"] The device never takes a new server identity from the server itself. The
banner (`server.identity`) offers exactly two ways back, as two buttons:

1. **"Code von einem anderen Gerät scannen"** (`server.fix.scan`), shown first when the account
   has another device. The dialog says: "Öffne {app} auf einem Gerät, das noch verbindet, und
   wähle dort Geräte und dann Gerät hinzufügen. Scanne den Code oder füge den Link hier ein."
   (`server.fix.scanBody`). It is the same field as in 4.3 (paste button, camera when present).
   An offer of this account only brings the new server identity along; this device does not pair
   again and keeps its name and folders. [ADR 6] Success: "Verbunden. Alles läuft wieder."
   (`server.fix.done`). An offer from another account: `error.server.otherAccount`. The other
   device's "Gerät hinzufügen" dialog simply expires; nothing joins.
2. **"Mit dem Betreiber vergleichen"** (`server.fix.compare`), the only way when no other device
   trusts the new identity, for example on the first device after the change. The dialog:

```text
| Servernummer vergleichen                                     |
| Bitte den Betreiber, auf dem Server diesen Befehl            |
| auszuführen: hangar-drive-server server-key-number           |
| Stimmen alle Zahlen mit diesen hier überein?                 |
|                                                              |
|      30417  88265  10394                                     |
|      57721  64008  29153                                     |
|                                                              |
|   [ Nein, nicht verbinden ]  [ Ja, gleiche Zahlen, verbinden ] |
```

- **Same shape as the safety number.** [ADR 6] Six groups of five digits, the layout people know
  from pairing, read group by group by the screen reader. The label is "Servernummer" /
  "server number" (`server.number.label`); it is always a row of numbers to compare, never a technical term.
- **The confirm button waits 1 s** after the dialog appears or the numbers change, as in
  section 5. [ADR 6]
- **Asked once more by the system.** [Security review L2] "Ja, gleiche Zahlen, verbinden" asks
  again in the operating system's dialog with the same numbers, as accepting a pairing does, so a
  click the person never made trusts no key. "Nein" there trusts nothing and shows the mismatch
  line below (`confirmServerNumber` answers `declined`).
- **Mismatch** ("Nein"): "Dann verbinde nicht. Sag dem Betreiber, dass die Zahlen nicht passen.
  Deine Dateien hier bleiben, wie sie sind." (`server.fix.mismatch`). The banner stays.
- **The command** in the text is a placeholder `{command}` filled by the app, so the CLI can be
  named once [Backend: the exact command of ADR 6].
- **Public certificates** (for example Let's Encrypt) need none of this: a renewal changes
  nothing the person sees. [ADR 6]

### 8.4 Server storage full

Four server limits, each with its own words, because each has a different remedy. The server
reports them through the feed `notice` kinds or as a refused upload or commit; the text is
always the app's own [ADR 5, ADR 3 change feed].

| Case | Trigger | Tray | Text and remedy |
| --- | --- | --- | --- |
| account quota | upload refused, live bytes at the quota [ADR 5] | Braucht dich | `quota.title`, `quota.body`: delete what you no longer need; earlier versions and the trash do not count; or ask the operator for more space |
| quota and headroom used up | even the small uploads a delete needs are refused [ADR 5 headroom] | Braucht dich | `quotaFull.title`, `quotaFull.body`: deleting does not work either now; only the operator can make room. Action "Fehlerbericht kopieren" |
| upload budget | this device or the account made its daily budget live [ADR 5] | no state of its own: the state follows 6.1 without the waiting files, with `budget.line` as the muted second line | nothing to do; the rest follows within a day |
| server disk reserve | the server refuses all uploads [ADR 5] | Braucht dich | `serverDisk.title`, `serverDisk.body`: only the operator can help |

- **Behavior.** Uploads stop, downloads continue, local files stay. Deletes still go through at a
  full quota, because the ADR gives them a small headroom, and the text says so: deleting is the
  way to free space. [ADR 5, Design] Restores that bring back bytes count against the quota and
  the budget (9.2).
- **Headroom used up.** [ADR 5] The headroom is small (default 1 % of the quota, at least
  64 MiB) and is only used up in rare cases, for example many deletes in many folders while the
  quota is full. Then the app stops offering deletion as the remedy and says plainly that only
  the operator can help. Local deletes stay pending, nothing is lost, and they go out by
  themselves once there is room. [Design]
- **Budget is calm.** [Design] Reaching the daily budget is normal after a large first upload. It
  is never "Braucht dich", never a notification and never "wird synchronisiert": the files wait
  and the muted line says until when, as for metered networks (6.1).
- **Action.** "Fehlerbericht kopieren" for the operator cases. No fake "empty trash" button
  (section 9.3). [ADR 5, Design]

#### Quiet notices from the server

[ADR 3 change feed `notice`, ADR 5] Besides the anomaly pin (9.4), the server sends notices that
need no decision from the person. Each one is a muted line under the storage line of the main
window (6.3) and in Settings, Konto, never a banner, a notification or a tray state, and it
disappears when the server stops sending it. [Design]

| Notice kind | Text (de) | Why it is quiet |
| --- | --- | --- |
| retained bytes above the quota | `notice.retained`: Alte Versionen belegen auf deinem Server gerade viel Platz. Der Betreiber weiß Bescheid. Du musst nichts tun. | old versions do not count against the quota; only the operator's disk is affected |
| budget of another device | `notice.budgetDevice`: „{device}“ hat heute sehr viel hochgeladen. Warst du das nicht, schau unter Geräte nach. | usually a large first upload; the anomaly pin (9.4) covers the dangerous case |
| minimum count cap reached | `notice.minCount`: Dein Server hebt alte Versionen jetzt nur noch {days} Tage auf, auch in Ordnern, die sich selten ändern. Der Betreiber weiß Bescheid. | versions within the window are not affected; only very old versions of rarely changed folders expire earlier than before |

The budget of this device is not a notice line; it is `budget.line` (6.1).

### 8.5 Disk full on this computer

- **Banner.** "Auf diesem Computer ist der Speicher voll" / "Hangar Drive lädt weiter herunter,
  sobald wieder {size} frei sind." Uploads continue. [Design]
- **Action.** "Speicher anzeigen" opens the OS storage settings. [Design]

### 8.6 The server shows an older state

- **Trigger.** [ADR 4, threat model 3.4] The server's answer does not descend from the frontier
  this device has verified, or a fork is detected.
- **Behavior.** Only that folder stops; local files stay and can still be edited; they sync when
  the server is consistent again. Tray "Braucht dich". [ADR 4, Design]
- **Banner.** "„Fotos“ ist angehalten" / "Dein Server zeigt einen älteren Stand, als dieses Gerät
  schon kannte. Meist hat der Betreiber eine Sicherung zurückgespielt. Deine Dateien hier sind
  sicher." (`older.title`, `older.body`)
- **Actions.** "Fortsetzen …" (`older.resume`, default) opens the dialog below; "Jetzt noch mal
  prüfen" (`older.check`). The check also repeats by itself every 15 minutes; if the server
  shows the newer state again, the banner disappears and nothing else happens. [Design]
- **Never automatic.** [ADR 4 "Re-anchor"] The folder stays paused until the person confirms on
  this device. The same dialog serves the rare case in which the server lost the record of an
  old version after a long offline period [ADR 4 "Long offline"].

#### Continuing with the server's state (re-anchor)

The dialog has one decision per screen. [ADR 4 "Re-anchor" step 1, Design]

**Screen 1: compare.**

```text
| Erst mit einem anderen Gerät vergleichen                     |
| Öffne {app} auf einem anderen Gerät und wähle beim Ordner    |
| „Fotos“ Ordnernummer anzeigen. Stimmen die Zahlen mit        |
| diesen hier überein?                                         |
|                                                              |
|      71530  04482  93127                                     |
|      18865  50213  66790                                     |
|                                                              |
|   [ Nein, sie sind anders ]   [ Ja, gleiche Zahlen ]         |
|                                                              |
|   Kein anderes Gerät da? (link)                              |
```

- **What the numbers are.** [ADR 4] This device shows the folder number of the state the server
  now presents. The other device shows the number of what it knows: its own state if the folder
  runs there, or also the server's state if the folder is paused there too. In both cases equal
  numbers mean both devices see the same server. The row menu of every folder therefore has
  "Ordnernummer anzeigen" (`folder.menu.number`). [Design]
- **Always current.** [ADR 4 "Re-anchor" step 1] Before a running device shows its number, it
  checks with the server once, so a device that has not synced since the backup was restored
  does not show an outdated number and cause a false "anders". Without a connection it shows
  `folder.number.offline` instead of a number.
- **"Ja, gleiche Zahlen"** waits 1 s before it takes a click, as in section 5. [ADR 6, threat
  model R8]

**Screen 2: confirm.** After "Ja, gleiche Zahlen":

```text
| „Fotos“ fortsetzen?                                          |
| Deine Dateien auf diesem Gerät werden mit dem Stand auf dem  |
| Server zusammengeführt. Weicht eine Datei ab, bleiben beide  |
| Fassungen erhalten.                                          |
| Frühere Versionen aus der Zeit nach der Sicherung gehen      |
| dabei verloren. Was nur in solchen Zwischenständen war, ist  |
| danach nicht mehr da.                                        |
|                                                              |
|                       [ Abbrechen ]   [ Fortsetzen ]         |
```

- **Honest about the result.** [ADR 4 "Re-anchor" steps 3 and 4, "What the history loses"] The
  text promises neither "nothing is lost" nor "only newer files are uploaded". What happens: the
  local state is merged with the server's state by the normal rules, so differing files become
  two versions (7.1), and the versions between the restored backup and what this device knew are
  gone from "Frühere Versionen". A file that existed only in such a version (changed again later,
  or deleted later) cannot be brought back.
- **"Fortsetzen"** waits 1 s, then merges and syncs. Success line: "„Fotos“ läuft wieder."
  (`older.done`). If the account has other devices, a second line follows: "Ist der Ordner auf
  einem anderen Gerät auch angehalten, bestätige es dort genauso." (`older.donePerDevice`),
  because every device confirms for itself and none follows another. [ADR 4]

**No other device.** "Kein anderes Gerät da?" leads to a confirmation without comparing:

```text
| Ohne Vergleich fortsetzen?                                   |
| Ohne zweites Gerät kann {app} nicht prüfen, ob dein Server   |
| wirklich nur eine Sicherung zurückgespielt hat. Mach das nur,|
| wenn der Betreiber es dir bestätigt hat.                     |
| (then the two paragraphs of screen 2)                        |
|                                                              |
|               [ Abbrechen ]   [ Ohne Vergleich fortsetzen ]  |
```

- The button waits 1 s, like every confirmation in this flow. [ADR 4 "Residual risk"] The extra
  sentence is the whole cost of skipping the comparison, in words a person can act on: ask the
  operator first.

**Different numbers.** After "Nein, sie sind anders":

```text
| Dann setze nicht fort                                        |
| Deine Geräte sehen gerade nicht denselben Stand deines       |
| Servers. Sag dem Betreiber Bescheid und schick ihm den       |
| Fehlerbericht. Deine Dateien hier bleiben, wie sie sind.     |
|                                                              |
|                 [ Fehlerbericht kopieren ]   [ Schließen ]   |
```

- The folder stays paused and the banner stays. No talk of attackers; this is the fork case of
  [ADR 4 "Forks"], and the comparison just showed it. [Design]

### 8.7 No news from the other devices (freeze)

- **Trigger.** [ADR 4] This device has seen no new commit from any sibling device for 14 days
  while it was online, and the account has more than one device. [Design for the threshold]
- **Presentation.** Not a problem state, a quiet line in the folder's details: "Seit 14 Tagen
  nichts Neues von deinen anderen Geräten. Wenn du dort etwas geändert hast, vergleiche die
  Ordnernummer." with "Ordnernummer vergleichen", which shows the folder safety number in the same
  six groups of five as the pairing screen. [Design]

### 8.9 Changes from a removed device

- **Trigger.** [ADR 4 "A resumable job", security review H1] A device's delta check finds saved
  states of a device that the account log has removed, without the barrier the removing device
  writes after a removal. The engine does not take them in; the folder stops
  (`StopReason::RemovedHeads`), the warning `removedHeads` appears and the event `removedHeads`
  asks the window to put the question in front. This is a strong sign of a malicious server or a
  leaked key, so the question comes as a dialog, opened once by itself like 8.1, and the tray goes
  to "Braucht dich".
- **Text.** One sentence, no technical terms: "In „Fotos“ sind Änderungen von „Alter Laptop“
  angekommen, obwohl das Gerät nicht mehr zu deinem Konto gehört." When the name is unknown or
  several devices are involved: "... von {count} Geräten ..., die nicht mehr zu deinem Konto
  gehören." Below, muted: "Am sichersten machst du sie rückgängig. Bis du dich entscheidest,
  wartet der Ordner." (`heads.*`)
- **Two ways, one default.** "Ansehen und rückgängig machen" (primary, focused) takes the changes
  in (`acceptRemovedHeads`) and opens the earlier versions at the last state before the first of
  them, labelled "Vor den Änderungen von „Alter Laptop“": this is "Undo a device" of 9.4, and the
  reset works as there. "Übernehmen" takes them in and says "Übernommen. „Fotos“ wird wieder
  synchronisiert." with "Doch rückgängig machen" as the way back. Both take the changes in, so
  both hold back clicks for 1 s after the dialog appears. [Design]
- **Deciding later.** Escape closes the dialog without deciding: the folder stays stopped
  ("Angehalten: Änderungen eines entfernten Geräts"), the banner stays with "Entscheiden", and the
  focus goes to the banner. A new `removedHeads` event brings the question back. [Design]

### 8.8 This device was removed, or the app is too old

| Case | Text | Actions |
| --- | --- | --- |
| removed by another device | "Dieses Gerät wurde von „{device}“ entfernt. Deine Dateien bleiben hier, werden aber nicht mehr synchronisiert." | "Wieder koppeln" (opens 4.3), "Das war ich nicht" (explains the recovery sheet path) |
| removed, the remover unknown (the server answers `deviceRemoved` at sign-in) | "Dieses Gerät wurde aus deinem Konto entfernt. Deine Dateien bleiben hier, werden aber nicht mehr synchronisiert." | as above |
| the server needs a newer app | "Hangar Drive braucht ein Update, um weiter zu synchronisieren." | "Jetzt aktualisieren"; the result shows as a line ("Version {version} ist installiert. …" or "Es gibt noch keine neuere Version. …") |
| the same, in a build that cannot update itself (no updater key, `About.updates` false or `installUpdate` refused with "updates are off") | "Hangar Drive braucht ein Update, um weiter zu synchronisieren. Installiere die neue Version, dann geht es von selbst weiter." | none: the button is hidden, no error is shown |
| the server refuses this device | "Dein Server lässt dieses Gerät nicht mehr herein." | "Wieder koppeln", "Fehlerbericht kopieren" |

[ADR 6 for revocation, Design for the texts]

## 9. Restore

All restore views open from a folder row ("Frühere Versionen", "Papierkorb") or from an activity
entry. They are one view with two tabs, so there is one place to learn. [Design]

### 9.1 Earlier versions of a folder (timeline)

```text
+------------------------------------------------------------------+
| Frühere Versionen von „Hangar Drive“           [Versionen|Papierkorb] |
+-------------------------+----------------------------------------+
| Heute                   | Stand von heute, 11:20                 |
|  > 14:31 Arbeitslaptop  |  Gegenüber jetzt: 3 Dateien anders,    |
|    3 Dateien geändert   |  1 Datei fehlt                         |
|    11:20 Laptop         |                                        |
|    12 Dateien neu       |  [folder] Projekte                     |
| Gestern                 |     Bericht.docx      anders  [Wiederh.] |
|    18:02 Laptop         |     Plan.xlsx                          |
|    1 Datei gelöscht     |  Notizen.txt          fehlt   [Wiederh.] |
| 23. November            |                                        |
|    ...                  |  [ Ganzen Ordner auf diesen Stand      |
|                         |    zurücksetzen ]                      |
| Versionen bleiben       |                                        |
| {days} Tage erhalten.   |                                        |
+-------------------------+----------------------------------------+
```

- **A list, not a slider.** [Design] The timeline is a vertical list grouped by day: a slider
  cannot be read by a screen reader in any useful way, is fiddly at 640 px, and hides the "who and
  what" that people need to recognize a moment. The list is a listbox: arrow keys move, the right
  side updates at once.
- **Sessions, not commits.** [Design] Commits of one device less than 10 minutes apart form one
  entry ("14:31 Arbeitslaptop, 3 Dateien geändert"). The entry shows the time of its last commit.
- **Right side.** [Design] The folder as it was at that moment, as a tree, with each file's
  difference to now (anders, fehlt jetzt, neu seitdem). A filter "Nur Unterschiede" is on by
  default.
- **Reset the whole folder.** [Design] "Ganzen Ordner auf diesen Stand zurücksetzen"
  asks once: "„Hangar Drive“ wird auf den Stand von heute, 11:20 zurückgesetzt. Der jetzige Stand
  bleibt als Version erhalten, du kannst also auch das rückgängig machen." [ADR 5: a restore is a
  new commit on the current head; nothing in the history is removed]
- **Expired versions.** [ADR 5] Versions whose tree the server no longer holds cannot be
  restored, and the server no longer keeps their time, so they cannot be placed under a day. The
  list ends with one muted line for all of them, "{count} ältere Versionen sind nicht mehr
  verfügbar" (`restore.expiredOlder`, one and other form), followed by the retention line.
  [Design]
- **After a re-anchor** (8.6). [ADR 4 "What the history loses"] The version a device wrote when
  it continued with the server's state carries a muted marker line below its entry: "Hier hat
  dein Server einen älteren Stand zurückgespielt. Zwischenstände von davor fehlen."
  (`restore.reanchored`). It appears on every device, so nobody searches for a version that no
  longer exists. The marker comes from bit 0 of the signed commit `flags` [ADR 4 "Re-anchor
  mark"].
- **Retention line.** "Versionen bleiben {days} Tage erhalten. Das legt dein Server fest." The
  value comes from the server. [ADR 5, Backend]
- **When a restore must wait or is refused.** [ADR 5 "Only while retained", "Quota and retained
  storage"] Bringing back an old version makes its bytes count again, so the server can hold it
  back. The app never shows a technical refusal; the line appears next to the button that started
  the restore:

| Situation | What the app does | Text (key) |
| --- | --- | --- |
| the daily upload budget is used up | keeps the restore as a pending job and runs it by itself once the budget allows, at the latest within a day; the line has "Abbrechen" | `restore.waitBudget`: Wartet: Heute wurde schon sehr viel hochgeladen. Das Wiederherstellen läuft von selbst, spätestens morgen. |
| the quota would be exceeded | does nothing, because waiting for space can last for ever | `restore.noSpace`: Dafür ist auf deinem Server kein Platz. Lösch Dateien, die du nicht mehr brauchst, oder frag den Betreiber nach mehr Platz. Es wurde nichts verändert. |
| the version expired meanwhile | does nothing; the entry turns into the expired line | `restore.expired`: Diese Version ist nicht mehr verfügbar. Es wurde nichts verändert. |
| network or server error | does nothing | `error.restore.failed` |

  A pending whole-folder reset is computed again when it runs, on the then current state, so
  whatever changed in the meantime stays as a version too. [ADR 5, Design]

### 9.2 One file from an earlier version

- From the tree on the right, from an activity entry, or from the trash. [Design]
- **"Wiederherstellen"** puts that version back under its name. No confirmation: the current
  version becomes a version itself, and a feedback line near the button says "Wiederhergestellt.
  Die vorherige Fassung ist unter Frühere Versionen." with "Rückgängig". [Design]
- **Name taken.** [ADR 5] If a different file now holds the name, the restored one becomes
  `<name> (restored <date>).<ext>`, with the word in the device's UI language
  (`restore.fileWord`), and the feedback line says so.
- **"Als Kopie speichern"** in the row menu writes the old version under that same
  `(restored <date>)` pattern next to the current file, so there is one pattern to learn.
  [Design]
- **Versions of one file**: the row menu "Alle Versionen dieser Datei" filters the timeline to
  sessions that changed that file. [Design]
- **Waiting or refused.** The same cases and texts as in 9.1 apply, shown in the feedback line of
  the row. While a restore waits, the row shows "Wartet" (`restore.file.waiting`) and the file
  keeps its current content. The trash (9.3) uses the same line. [ADR 5, Design]

> [!question] Unverified
> An Explorer context menu entry "Frühere Versionen in Hangar Drive" would be the most natural
> entry point. On Windows 11 the modern context menu needs `IExplorerCommand` and package identity
> (a sparse package). Not in version 1 until checked.

### 9.3 Trash

```text
| Papierkorb von „Hangar Drive“      [ Suchen ...          ]    |
|  Notizen.txt     Projekte\       gelöscht gestern, Laptop  [Wiederherstellen] |
|  Alt.pdf         (Ordner)\       gelöscht 20. Nov.         [Wiederherstellen] |
|  Gelöschte Dateien bleiben {days} Tage, dann entfernt dein    |
|  Server sie. Endgültig löschen kann nur der Betreiber.        |
```

- **Content.** [ADR 5, threat model 4.1] Every file that exists in a retained version but not in
  the current state, with its last path, deletion time and device. Multiple selection with Shift
  and Ctrl; "Wiederherstellen" restores to the old path (and recreates missing parent folders).
- **No "empty trash" button.** [Design] The ADR makes "empty trash" only a request the server
  ignores until the window has passed. A button that seems to delete but does not is dishonest
  and, for private files, harmful. The trash says plainly who can delete for good. [ADR 5]
- **Search** filters by name as one types. [Design]

### 9.4 Suspected ransomware

- **Trigger.** [ADR 5] The server's anomaly pinning fires: a burst of replaced or dropped objects,
  attributed to the device that signed those commits. It pins the last commit before the burst
  for up to 90 days and tells all devices. A pin can lapse earlier when the account's pin cap is
  full (ADR 5 "Pin cap, a lasting invariant"); the version then stays for the normal retention
  window, which the banner states as the guaranteed minimum.
- **Presentation** on every device: notification, tray "Braucht dich", and a red banner (the only
  red one):

```text
| Auf „Arbeitslaptop“ wurden sehr viele Dateien verändert       |
| Das kann ein Schadprogramm sein. Der Stand davor ist gesichert |
| und bleibt mindestens {days} Tage erhalten.                   |
|                 [ Was jetzt? ]   [ Das war ich ]              |
```

- **"Was jetzt?"** opens a guided dialog with three numbered steps, because order matters:
  1. "Trenne „Arbeitslaptop“ vom Netz oder entferne ihn hier." with "Gerät entfernen" (section
     10.2). Restoring first would be undone by the infected device. [Design]
  2. "Prüfe das Gerät mit deinem Virenschutz." (text only)
  3. "Hol den Stand von davor zurück." with "Stand vor den Änderungen ansehen", which opens the
     timeline (9.1) preselected on **the last version before the first commit of that device in
     the burst** [ADR 5 "Undo a device", threat model 4.2], labelled "Vor den Änderungen von
     „Arbeitslaptop“". Reset works as in 9.1, except that it normally does not wait for the daily
     budget, because the pinned version is exempt from it within the pin restore allowance [ADR 5
     "Upload budgets"].
- **"Das war ich"** (for example after re-saving a photo library) hides the banner on this device
  only. [ADR 5 "No shared dismissal"] Every other device keeps its banner until the person chooses
  "Das war ich" there too; otherwise a hijacked device could silence the one warning about itself
  everywhere. The feedback line says so: "Ausgeblendet auf diesem Gerät. Auf deinen anderen
  Geräten siehst du den Hinweis noch." (`suspect.meDone`). The pin stays on the server until its
  90 days end, it lapses under the pin cap, or the operator lifts it. `{days}` in the banner is the
  retention window the server reports, the minimum it guarantees.
- **Manual path** without a server alert [ADR 5 "Undo a device"]: the timeline has an action
  "Stand vor Änderungen von ..." with two fields, the device and "ab" (a date, default the oldest
  retained version). It selects the last version before the first one after that date that
  contains a change by that device, and shows the same advice to remove the device first.
  [Design for the two fields]

## 10. Devices

### 10.1 The list

```text
| Deine Geräte                                  [ Gerät hinzufügen ] |
|  [laptop] Arbeitslaptop   Dieses Gerät        seit 26. Nov.   [...] |
|  [pc]     Büro-PC         zuletzt vor 5 Min.  seit 2. Nov.    [...] |
|  [pc]     Alter Laptop    zuletzt vor 3 Monaten                [...] |
|                                                               |
|  Wiederherstellungscode   erstellt am 26. Nov.  [ Neu erzeugen ] |
```

- Rows: name, "Dieses Gerät" or last seen, added date. Row menu: "Umbenennen" (for every device,
  because all are the person's own), "Sicherheitsnummer anzeigen", "Entfernen".
  [Design]
- A device not seen for 90 days gets a muted hint "Lange nicht gesehen. Entferne es, wenn du es
  nicht mehr hast." [Design]
- The recovery device of the account log is not shown as a device but as the recovery code row.
  [Design]

### 10.2 Removing a device

```text
| „Alter Laptop“ entfernen?                                    |
| Danach kann dieses Gerät nichts mehr synchronisieren und     |
| keine neuen Dateien mehr lesen.                              |
| Was schon darauf liegt, bleibt dort: Hangar Drive kann auf   |
| einem anderen Gerät nichts aus der Ferne löschen.            |
| Verloren oder gestohlen? Dann entferne es jetzt.             |
|                              [ Abbrechen ]  [ Entfernen ]    |
```

- **What happens** [ADR 4, threat model 2.4]: a remove entry in the account log, the server
  revokes the device's sessions at once, the account epoch rotates, every folder gets a new key
  generation. The person sees none of these words; the dialog states the two effects that matter
  (no more sync, no new files) and the one limit (existing copies stay).
- **Re-encrypting old content** [ADR 4: optional, off by default] is not offered in this dialog.
  It only helps against a removed device that never downloaded the data, and a checkbox with that
  explanation would confuse almost everyone. [Design, see open questions]
- **Default** is "Abbrechen"; "Entfernen" is danger style. [Design]
- **Removing this device** is "Dieses Gerät trennen" in its row menu: "Deine Dateien bleiben in
  den Ordnern, werden aber nicht mehr synchronisiert. Du kannst das Gerät später wieder koppeln."
  [Design]
- **Removing the last device** is refused while no other device exists: "Das ist dein einziges
  Gerät. Ohne Gerät kommst du nur noch mit dem Wiederherstellungscode an deine Dateien." with
  "Trotzdem trennen" behind a second confirmation. [Design]

### 10.3 New recovery code

- **When.** After a recovery (mandatory, 4.4), and whenever the person thinks the code was seen or
  lost. [ADR 4]
- **Flow.** The same screen as setup step 2, introduced by: "Der neue Code ersetzt den alten. Der
  alte funktioniert danach nicht mehr. Wirf das alte Blatt weg." The old recovery device is removed
  only after the group check succeeds, so closing the dialog midway leaves the old code valid.
  [Design, Backend]

## 11. Settings

As few as possible; every entry needs a reason that holds against "just pick a good default".

| Setting | Default | Why it exists |
| --- | --- | --- |
| **Beim Anmelden starten** / Start at sign-in | on | The owner wants autostart on by default. A switch is still needed: people who sync only now and then, shared computers, and the expectation from every OS that background apps can be stopped from starting. [Design] |
| **Sprache** / Language | System | Twelve languages [project rules]; the system language is not always the one a person reads best, and the sister app has the same picker. [Design] |

That is all. Below them, not settings but information:

- **Konto:** server address, used storage, retention ("Versionen bleiben 30 Tage erhalten").
- **Hilfe:** "Dieses Gerät zurücksetzen" (security review L1): the account is forgotten on this
  device, the files stay. The question is asked once, in place, with "Abbrechen" focused and
  "Zurücksetzen" in the danger style; afterwards the window shows the welcome (4.1), from where
  the person sets up a new account or pairs again. [Design]
- **Über Hangar Drive:** version, "Fehlerbericht speichern" (a text file with versions, states and
  error codes, never file names or keys, shown before saving), the honest notes "Deine Dateien
  liegen auf diesem Computer unverschlüsselt. Schalte die Laufwerksverschlüsselung deines
  Systems ein." [ADR Consequences] and "Auf dem Server sind deine Dateien verschlüsselt."

Deliberately left out, with the default that replaces them: [Design]

| Left out | Replaced by |
| --- | --- |
| Theme | follows the OS light or dark mode |
| Notifications on or off | the strict notification policy (6.4) and the OS's own per-app switch |
| Bandwidth limits | sync runs at low I/O and network priority; open question for metered networks |
| Ignore patterns | the built-in list of [ADR 7]; user-defined patterns are a non-goal [ADR 2] |
| Mass deletion threshold | fixed at 100 [ADR 5] |
| Device name | Devices, where it belongs |
| Folder location | row menu of the folder |
| Updates | automatic and signed [project rules], no switch |

## 12. Accessibility

- **Minimum window 640 × 420.** [Design] At that size the main window is one column; the restore
  view stacks the timeline above the tree, with the timeline collapsed to the selected entry
  plus "Andere Version wählen". Nothing scrolls horizontally. Text is never truncated without the
  full text being the accessible name and the tooltip.
- **Text scaling.** Layout holds at the Windows text size setting of 200 %; spacing uses the
  `--space-*` tokens, sizes are in `rem` against the 13 px root. [Design]
- **Keyboard.** [Design]
  - Tab order follows reading order: status, banner, folder list, activity list, header buttons
    last (they are the least used).
  - Lists are single tab stops with arrow keys inside (roving tabindex); Enter opens, Shift+F10 or
    the context menu key opens the row menu.
  - Every dialog traps focus, Escape closes it without deciding, focus returns to the element that
    opened it (the sister app's `Dialog`).
  - Global shortcuts inside the window only: F1 opens help, Ctrl+, opens the settings. No
    Ctrl+letter alone where a text field needs it. [project rules]
  - The tray menu is reachable with Win+B, then arrow keys, Enter and the context menu key.

> [!question] Unverified
> Win+B focusing the notification area, and the tray icon opening its menu with the context menu
> key, are assumed for Windows 10 1809 and 11. Check with Narrator on both.
- **Screen reader.** [Design]
  - The status sentence is a `role="status"` region; it announces only state changes (up to
    date, syncing, paused, offline, needs you), never per file progress.
  - Banners that need a decision use `role="alert"`; informational banners use `role="status"`.
  - Folder and activity rows have one accessible name each: "Fotos, D:\Fotos, 120 Dateien werden
    hochgeladen".
  - Codes are read group by group ("Gruppe 3: 9 H 4 T"); the code box has a "Vorlesen" pattern
    through `aria-label` with spaced characters.
  - The tray tooltip always contains the state in words.
- **Contrast** of the existing tokens, measured with the WCAG formula on 2026-11-26 [Design]:

| Pair | Dark | Light |
| --- | --- | --- |
| `--text` on `--bg` / `--panel` / `--panel-raised` | 13.8 / 12.8 / 11.7 | 15.8 / 14.5 / 15.8 |
| `--muted` on the same | 6.0 / 5.5 / 5.1 | 6.1 / 5.6 / 6.1 |
| `--accent` on the same | 7.7 / 7.1 / 6.5 | 5.2 / 4.8 / 5.2 |
| `--ok` on the same | 6.6 / 6.1 / 5.6 | 5.1 / 4.7 / 5.1 |
| `--warn` on the same | 6.7 / 6.2 / 5.7 | 4.9 / **4.5 (4.46)** / 4.9 |
| `--error` on the same | 6.6 / 6.1 / 5.6 | 5.4 / 4.9 / 5.4 |
| `--on-primary` on `--primary` | 5.2 | 5.2 |
| white on `--danger` | 5.9 | 5.4 |
| `--border` on `--bg` | 1.4 | 1.5 |

  Two consequences: warning text in light mode must not sit on `--panel` (use `--bg` or
  `--panel-raised`, or darken `--warn` slightly), and `--border` is below the 3 : 1 needed for the
  outline of inputs and the code box, so those use `--muted` for their outline. State is never
  shown by color alone: every state has a shape and a word.
- **Forced colors** (Windows high contrast): icons use `currentColor`, banners keep a visible
  border, focus rings use `Highlight`. [Design]
- **Reduced motion.** The base styles already zero transitions. The only motion in this concept is
  the dialog and banner entrance (opacity plus 4 px, 200 ms, `--ease-out`); nothing moves on its
  own. [Design]
- **Targets.** Buttons and row actions at least 32 px high with 8 px between them in this desktop
  app; the row menu button is 32 × 32 px. [Design]

## 13. UI text catalog

German is the source and uses "du"; English is the fallback. The other ten languages follow in
the i18n module [project rules]. Placeholders in braces are identical in all languages. The
existing keys `empty.title` and `empty.body` are replaced by `main.empty.*`; `app.name` stays.

The tables match `src/i18n.ts` for German and English (aligned on 2026-11-26, again after the
sync engine flows). The recovery sheet's texts (`sheet.*`) are part of the window's module now:
the window words the sheet and the backend only lays it out (4.4).

### Plural forms

Every text with a number in it exists in the plural forms of each language, because "1 Dateien"
is the kind of small mistake that makes an app feel careless. [Design]

- **Mechanism.** The category comes from `Intl.PluralRules` for the current UI language:
  `new Intl.PluralRules(locale).select(count)`. The i18n module stores one key per category, as
  the base key plus a suffix: `.one`, `.other` and, where the language uses them, `.few` and
  `.many` (also `.zero` and `.two`, if one of the twelve languages reports them). The lookup is
  `t("names.banner", { count })`; the caller never picks the suffix.
- **Which number decides.** The placeholder `{count}`, or `{days}` in texts about days. A text
  with two numbers (`restore.diff`) is built from one plural key per number, put into a frame key
  with named slots, never by joining strings in code.
- **The number itself** is formatted with `Intl.NumberFormat` for the same locale (`1.234` in
  German, `1,234` in English), after the category is chosen from the raw number.
- **German and English** need `.one` and `.other`; the tables below give both. Languages such as
  Polish, Czech or Russian also need `.few` and `.many`; the translator fills exactly the
  categories that `resolvedOptions().pluralCategories` lists for the language.
- **Tests.** A unit test checks, for every language, that each plural key has exactly the
  categories the language reports, that `.other` always exists, and that every form contains the
  same placeholders. A missing form falls back to `.other` of that language, then to English.
  [project rules: every UI text in the i18n module]
- **Zero** is never shown as a count. A banner, line or badge whose count drops to 0 disappears,
  and empty states have their own texts (`main.empty.*`, `trash.empty`).

### 13.1 Welcome and setup

| Key | de | en |
| --- | --- | --- |
| `welcome.title` | Willkommen bei {app} | Welcome to {app} |
| `welcome.body` | Deine Dateien auf allen deinen Geräten, auf deinem eigenen Server. Nur deine Geräte können sie lesen. | Your files on all your devices, on your own server. Only your devices can read them. |
| `welcome.invite` | Mit Einladungslink starten | Start with an invite link |
| `welcome.pair` | Ich nutze {app} schon auf einem anderen Gerät | I already use {app} on another device |
| `welcome.recover` | Kein Gerät mehr da? Wiederherstellungsblatt nutzen | No device left? Use your recovery sheet |
| `setup.step` | Schritt {step} von {total} | Step {step} of {total} |
| `setup.back` | Zurück | Back |
| `setup.next` | Weiter | Continue |
| `setup.done` | Fertig | Done |
| `setup.connect.title` | Mit deinem Server verbinden | Connect to your server |
| `setup.connect.body` | Füge den Einladungslink ein, den du vom Betreiber deines Servers bekommen hast. | Paste the invite link you got from the person who runs your server. |
| `setup.connect.label` | Einladungslink | Invite link |
| `setup.connect.paste` | Einfügen | Paste |
| `setup.connect.scan` | Mit Kamera scannen | Scan with camera |
| `setup.connect.checking` | Einladung wird geprüft … | Checking the invite … |
| `setup.connect.ok` | Verbunden mit {host} | Connected to {host} |
| `setup.connect.pinnedTitle` | Server mit eigenem Zertifikat | A server with its own certificate |
| `setup.connect.pinned` | Dieser Server hat kein öffentliches Zertifikat. {app} vertraut ihm, weil der Link es so festlegt. Nimm den Link nur an, wenn er direkt vom Betreiber deines Servers kommt. | This server has no public certificate. {app} trusts it because the link says so. Only accept the link if it comes straight from the person who runs your server. |
| `link.isInvite` | Das ist ein Einladungslink. Damit richtest du ein neues Konto ein. | This is an invite link. It sets up a new account. |
| `link.isPair` | Das ist ein Kopplungslink von einem deiner Geräte. | This is a pairing link from one of your devices. |
| `link.isRecover` | Das ist der Link von deinem Wiederherstellungsblatt. | This is the link from your recovery sheet. |
| `link.toInvite` | Neues Konto einrichten | Set up a new account |
| `link.toPair` | Stattdessen koppeln | Pair instead |
| `link.toRecover` | Mit dem Blatt einrichten | Set up with the sheet |
| `link.needPair` | Hier gehört ein Kopplungslink hin. | This needs a pairing link. |
| `link.notNeeded.title` | Dieses Gerät ist schon eingerichtet | This device is already set up |
| `link.notNeeded.body` | Hier brauchst du den Link nicht. Öffne ihn auf dem Gerät, das du neu einrichten willst. | You do not need this link here. Open it on the device you want to set up. |
| `setup.deviceName.label` | Name dieses Geräts | Name of this device |
| `setup.deviceName.help` | So erkennst du es später in der Geräteliste. | This is how you will recognize it in your device list. |
| `recovery.title` | Dein Wiederherstellungscode | Your recovery code |
| `recovery.body` | Wenn du alle Geräte verlierst, holt dieser Code deine Dateien zurück. Es gibt keinen anderen Weg, auch nicht über den Betreiber. | If you lose all your devices, this code gets your files back. There is no other way, not even through the operator. |
| `recovery.print` | Drucken | Print |
| `recovery.save` | Als Datei speichern | Save as file |
| `recovery.saveElsewhere` | Anderen Ort wählen | Choose another place |
| `recovery.copy` | Kopieren | Copy |
| `recovery.copied` | Kopiert. Er wird nach 1 Minute aus der Zwischenablage entfernt. | Copied. It will be removed from the clipboard after 1 minute. |
| `recovery.saved` | Gespeichert: {path} | Saved: {path} |
| `recovery.keepSafe` | Bewahre ihn auf wie einen Haustürschlüssel: Wer ihn hat, kann deine Dateien lesen. | Keep it like a house key: whoever has it can read your files. |
| `recovery.confirmSaved` | Ich habe ihn gesichert | I have saved it |
| `recovery.check.title` | Kurz prüfen | Quick check |
| `recovery.check.body` | Tippe die {group}. Gruppe deines Codes ab. | Type group {group} of your code. |
| `recovery.check.label` | Gruppe {group} | Group {group} |
| `recovery.check.confirm` | Bestätigen | Confirm |
| `recovery.check.wrong` | Das passt nicht. Schau noch mal auf dein Blatt oder in deine Datei. | That does not match. Check your sheet or your file again. |
| `sheet.more` | Was noch auf dem Blatt steht | What else is on the sheet |
| `sheet.title` | {app}: Wiederherstellungsblatt | {app}: recovery sheet |
| `sheet.serverId` | Server-Kennung | Server ID |
| `sheet.accountId` | Konto-Kennung | Account ID |
| `sheet.anchor` | Prüfwert des Kontos | Account check value |
| `sheet.pin` | Prüfwert des Servers | Server check value |
| `sheet.link` | Link zum Einfügen | Link to paste |
| `sheet.date` | Erstellt am | Created on |
| `sheet.device` | Gerät | Device |
| `sheet.note.what` | Mit diesem Code holst du deine Dateien zurück, wenn du alle Geräte verloren hast. | This code brings your files back if you lose all your devices. |
| `sheet.note.access` | Wer den Code hat, kann zusammen mit deinem Server alle deine Dateien lesen. Bewahre das Blatt auf wie einen Haustürschlüssel. | Whoever has the code can read all your files together with your server. Keep this sheet like a house key. |
| `sheet.note.gone` | Ohne diesen Code und ohne eines deiner Geräte lassen sich deine Dateien nicht mehr öffnen, auch nicht über den Betreiber. | Without this code and without any of your devices, your files can no longer be opened, not even through the operator. |
| `sheet.note.how` | So geht es: Installiere {app}, wähle „{door}“, füge den Link ein oder scanne den QR-Code und tippe den Code ab. | How it works: install {app}, choose “{door}”, paste the link or scan the QR code, then type the code. |
| `sheet.fileName` | {app} Wiederherstellungsblatt.txt | {app} recovery sheet.txt |
| `recovery.check.showAgain` | Code noch mal ansehen | Show the code again |
| `recovery.groupLabel` | Gruppe {index}: {chars} | Group {index}: {chars} |
| `folder.setup.title` | Wo sollen deine Dateien liegen? | Where should your files live? |
| `folder.setup.body` | Alles, was du in diesen Ordner legst, ist auch auf deinen anderen Geräten. Weitere Ordner kannst du später hinzufügen. | Everything you put in this folder is on your other devices too. You can add more folders later. |
| `folder.setup.defaultName` (backend) | Hangar Drive | Hangar Drive |
| `folder.setup.change` | Ändern | Change |
| `folder.setup.existing.one` | Der Ordner enthält schon {count} Datei, die hochgeladen wird. | The folder already contains {count} file. It will be uploaded. |
| `folder.setup.existing.other` | Der Ordner enthält schon {count} Dateien, die hochgeladen werden. | The folder already contains {count} files. They will be uploaded. |
| `merge.title.one` | In diesem Ordner liegt schon {count} Datei | This folder already holds {count} file |
| `merge.title.other` | In diesem Ordner liegen schon {count} Dateien | This folder already holds {count} files |
| `merge.body.one` | Die Datei kommt zu „{folder}“ dazu. Ist sie anders als auf deinen anderen Geräten, bleiben beide Fassungen erhalten. | It is added to “{folder}”. If it differs from the one on your other devices, both versions are kept. |
| `merge.body.other` | Die Dateien kommen zu „{folder}“ dazu. Ist eine Datei anders als auf deinen anderen Geräten, bleiben beide Fassungen erhalten. | They are added to “{folder}”. If a file differs from the one on your other devices, both versions are kept. |
| `merge.counting` | Dateien werden gezählt … | Counting files … |
| `merge.confirm` | Zusammenführen | Merge |
| `merge.chooseOther` | Anderen Ordner wählen | Choose another folder |
| `setup.ready.title` | Alles bereit | All set |
| `setup.ready.body` | Leg Dateien in deinen Ordner, den Rest erledigt {app}. | Put files in your folder, {app} does the rest. |
| `setup.ready.open` | Ordner öffnen | Open folder |
| `setup.ready.trayHint` | {app} läuft im Infobereich unten rechts. Zieh das Symbol in die Taskleiste, dann ist es immer zu sehen. | {app} runs in the notification area at the bottom right. Drag its icon onto the taskbar to keep it in view. |
| `app.name` | Hangar Drive | Hangar Drive |
| `name.blank` | Der Name ist leer. Gib einen Namen mit sichtbaren Zeichen ein. | The name is empty. Enter a name with visible characters. |
| `name.edgeWhitespace` | Der Name darf nicht mit einem Leerzeichen beginnen oder enden. | The name cannot start or end with a space. |
| `setup.pasteNoLink` | In der Zwischenablage ist kein Link von {app}. | There is no {app} link on the clipboard. |
| `recovery.codeLabel` | Wiederherstellungscode, 8 Gruppen | Recovery code, 8 groups |
| `setup.ready.continue` | Zum Fenster | Go to the window |

### 13.2 Pairing

| Key | de | en |
| --- | --- | --- |
| `pair.new.title` | Mit deinem anderen Gerät koppeln | Pair with your other device |
| `pair.new.body` | Öffne {app} auf dem anderen Gerät und wähle dort Geräte und dann Gerät hinzufügen. Füge den Kopplungslink dann hier ein. | Open {app} on the other device and choose Devices, then Add device. Then paste the pairing link here. |
| `pair.new.label` | Kopplungslink | Pairing link |
| `pair.new.typeInstead` | Kein Kopieren möglich? Code abtippen | Cannot copy? Type the code instead |
| `pair.new.serverLabel` | Serveradresse | Server address |
| `pair.new.codeLabel` | Kopplungscode | Pairing code |
| `pair.new.waiting` | Bestätige jetzt auf deinem anderen Gerät. Dort steht dieselbe Zahlenreihe: | Now confirm on your other device. It shows the same numbers: |
| `pair.new.waitingLink` | Bestätige jetzt auf deinem anderen Gerät. | Now confirm on your other device. |
| `pair.numbers.show` | Zahlen anzeigen | Show numbers |
| `pair.numbers.compare` | Zahlen vergleichen | Compare numbers |
| `pair.folders.title` | Welche Ordner sollen auf dieses Gerät? | Which folders should be on this device? |
| `pair.folders.free` | Auf diesem Computer sind {size} frei. | {size} free on this computer. |
| `pair.folders.tooBig` | Das sind {size} mehr, als frei ist. Die Downloads halten an, wenn der Speicher voll ist. | That is {size} more than is free. Downloads stop when the disk is full. |
| `pair.add.title` | Neues Gerät hinzufügen | Add a new device |
| `pair.add.step1` | Installiere {app} auf dem neuen Gerät. | Install {app} on the new device. |
| `pair.add.step2` | Wähle dort „Ich nutze {app} schon auf einem anderen Gerät“. | Choose “I already use {app} on another device” there. |
| `pair.add.step3` | Scanne diesen Code oder füge den Link dort ein. | Scan this code or paste the link there. |
| `pair.add.copyLink` | Link kopieren | Copy link |
| `pair.add.copied` | Link kopiert. Er wird nach 1 Minute aus der Zwischenablage entfernt. | Link copied. It will be removed from the clipboard after 1 minute. |
| `pair.add.validUntil` | Gültig bis {time}, nur für ein Gerät. | Valid until {time}, for one device only. |
| `pair.add.showCode` | Kein Kopieren möglich? Code zum Abtippen zeigen | Cannot copy? Show a code to type |
| `pair.add.expired` | Dieser Code ist abgelaufen. | This code has expired. |
| `pair.add.renew` | Neuen Code erzeugen | Create a new code |
| `pair.confirm.title` | „{device}“ möchte dazukommen. | “{device}” wants to join. |
| `pair.confirm.add` | Hinzufügen … | Add … |
| `pair.confirm.decline` | Ablehnen | Decline |
| `pair.confirm.body` | Auf dem neuen Gerät steht jetzt eine Zahlenreihe. Stimmt sie mit dieser hier überein? | The new device now shows a row of numbers. Does it match this one? |
| `pair.confirm.yes` | Ja, gleiche Zahlen, hinzufügen | Yes, same numbers, add it |
| `pair.confirm.no` | Nein, abbrechen | No, cancel |
| `pair.request.body` | Danach fragt dein System noch einmal nach und zeigt diese Zahlenreihe. Sag nur Ja, wenn das neue Gerät dieselbe zeigt. | Your system then asks once more and shows this row of numbers. Only say yes if the new device shows the same one. |
| `pair.mismatch` | Dann füge das Gerät nicht hinzu. Starte auf dem neuen Gerät noch mal von vorn. Passiert das wieder, sprich mit dem Betreiber deines Servers. | Then do not add the device. Start over on the new device. If it happens again, talk to the person who runs your server. |
| `pair.added` | „{device}“ ist jetzt dabei. | “{device}” has been added. |
| `pair.joined` | Gekoppelt. Gleich geht es weiter. | Paired. Just a moment. |
| `pair.check.title` | Mit diesem Server verbinden? | Connect to this server? |
| `pair.check.body` | Vergleiche Server und Konto mit deinem anderen Gerät. Dort stehen sie unter Geräte, dann Gerät hinzufügen. | Compare server and account with your other device. It shows them under Devices, then Add device. |
| `pair.check.server` | Server | Server |
| `pair.check.account` | Konto | Account |
| `pair.check.connect` | Verbinden | Connect |
| `pair.check.pinned` | Dieser Server hat kein öffentliches Zertifikat. {app} vertraut ihm, weil der Link es so festlegt. | This server has no public certificate. {app} trusts it because the link says so. |
| `pair.add.target` | Server {host}, Konto {account} | Server {host}, account {account} |
| `pair.devices.title` | Das sind deine Geräte? | Are these your devices? |
| `pair.devices.body` | Dieses Gerät ist jetzt mit dem Konto verbunden. Kennst du die Geräte nicht, brich ab: Dann wird es wieder getrennt, bevor Dateien übertragen werden. | This device is now connected to the account. If you do not know these devices, cancel: it is then disconnected before any files move. |
| `pair.devices.yes` | Ja, das sind meine | Yes, these are mine |
| `pair.devices.aborted` | Abgebrochen. Dieses Gerät ist wieder getrennt, es wurden keine Dateien übertragen. | Cancelled. This device is disconnected again, and no files were moved. |
| `safety.label` | Sicherheitsnummer | Safety number |
| `safety.group` | Gruppe {index}: {digits} | Group {index}: {digits} |
| `pair.new.linkInstead` | Doch lieber den Link einfügen | Paste the link after all |
| `pair.new.connect` | Koppeln | Pair |
| `pair.folders.none` | Wähle mindestens einen Ordner. | Choose at least one folder. |
| `pair.add.qrLabel` | QR-Code mit dem Kopplungslink | QR code with the pairing link |
| `pair.add.codeServer` | Serveradresse: {host} | Server address: {host} |

### 13.3 Recovery with the sheet

| Key | de | en |
| --- | --- | --- |
| `recover.title` | Mit dem Wiederherstellungsblatt einrichten | Set up with your recovery sheet |
| `recover.body` | Füge den Link von deinem Blatt ein oder scanne den QR-Code darauf. Den Code tippst du ab. | Paste the link from your sheet or scan the QR code on it. Then type the code. |
| `recover.codeLabel` | Wiederherstellungscode | Recovery code |
| `recover.cleanup.title` | Alte Geräte entfernen | Remove old devices |
| `recover.cleanup.body` | Diese Geräte gehören noch zu deinem Konto. Entferne die, die du nicht mehr hast. | These devices still belong to your account. Remove the ones you no longer have. |
| `recover.newCode` | Der alte Code ist jetzt verbraucht. Hier ist dein neuer. | The old code is used up now. Here is your new one. |
| `recover.linkLabel` | Link vom Blatt | Link from the sheet |
| `recover.linkOk` | Gefunden: {host} | Found: {host} |
| `recover.linkAccount` | Konto {account} | Account {account} |
| `recover.cleanup.remove` | „{device}“ entfernen | Remove “{device}” |

### 13.4 Tray

| Key | de | en |
| --- | --- | --- |
| `tray.state.upToDate` | Alles aktuell | Up to date |
| `tray.state.restUpToDate` | Alles andere ist aktuell | Everything else is up to date |
| `tray.state.syncing.one` | {count} Datei wird synchronisiert | Syncing {count} file |
| `tray.state.syncing.other` | {count} Dateien werden synchronisiert | Syncing {count} files |
| `tray.state.paused` | Angehalten bis {time} | Paused until {time} |
| `tray.state.pausedOpen` | Angehalten | Paused |
| `tray.state.offline` | Offline. Änderungen werden später synchronisiert. | Offline. Changes will sync later. |
| `tray.state.attention` | Braucht deine Hilfe | Needs your help |
| `tray.state.setup` | Einrichtung noch nicht fertig | Setup not finished |
| `tray.metered` | Große Dateien warten auf ein Netz ohne Datenlimit | Large files are waiting for an unmetered network |
| `tray.syncNow` | Jetzt synchronisieren | Sync now |
| `tray.tooltip` | {app}: {state} | {app}: {state} |
| `tray.last` | Zuletzt: {name}, {time} | Last: {name}, {time} |
| `tray.showProblem` | Problem ansehen | Show problem |
| `tray.openFolder` | Ordner öffnen | Open folder |
| `tray.openApp` | {app} öffnen | Open {app} |
| `tray.pause` | Pausieren | Pause |
| `tray.pause.hour` | Für 1 Stunde | For 1 hour |
| `tray.pause.tomorrow` | Bis morgen | Until tomorrow |
| `tray.pause.manual` | Bis ich fortsetze | Until I resume |
| `tray.resume` | Fortsetzen | Resume |
| `tray.quit` | Beenden | Quit |
| `tray.stillRunning` | {app} läuft im Infobereich weiter. | {app} keeps running in the notification area. |

### 13.5 Main window

| Key | de | en |
| --- | --- | --- |
| `main.devices` | Geräte | Devices |
| `main.settings` | Einstellungen | Settings |
| `main.status.lastSync` | Zuletzt synchronisiert um {time} | Last synced at {time} |
| `main.status.remaining` | Noch {size} | {size} left |
| `main.folders` | Ordner | Folders |
| `main.addFolder` | Ordner hinzufügen | Add folder |
| `main.addFolder.remote` | Auf deinen anderen Geräten gibt es noch: | Your other devices also have: |
| `main.activity` | Letzte Aktivitäten | Recent activity |
| `main.moreNotices.one` | Noch {count} weiterer Hinweis | {count} more notice |
| `main.moreNotices.other` | Noch {count} weitere Hinweise | {count} more notices |
| `main.storage` | {used} von {quota} auf deinem Server belegt | {used} of {quota} used on your server |
| `main.empty.title` | Noch kein Ordner | No folder yet |
| `main.empty.body` | Füge einen hinzu, dann ist er auf allen deinen Geräten. | Add one and it will be on all your devices. |
| `main.activity.empty` | Hier erscheint, was sich in deinen Ordnern ändert. | Changes in your folders will appear here. |
| `folder.status.upToDate` | Aktuell | Up to date |
| `folder.status.uploading.one` | {count} Datei wird hochgeladen | Uploading {count} file |
| `folder.status.uploading.other` | {count} Dateien werden hochgeladen | Uploading {count} files |
| `folder.status.downloading.one` | {count} Datei wird heruntergeladen | Downloading {count} file |
| `folder.status.downloading.other` | {count} Dateien werden heruntergeladen | Downloading {count} files |
| `folder.status.paused` | Angehalten | Paused |
| `folder.status.stopped` | Angehalten: {reason} | Stopped: {reason} |
| `folder.menu.open` | Im Explorer öffnen | Show in Explorer |
| `folder.menu.versions` | Frühere Versionen | Earlier versions |
| `folder.menu.trash` | Papierkorb | Trash |
| `folder.menu.pause` | Pausieren | Pause |
| `folder.menu.resume` | Fortsetzen | Resume |
| `folder.menu.number` | Ordnernummer anzeigen | Show folder number |
| `folder.number.offline` | Gerade keine Verbindung zum Server. Die Ordnernummer erscheint, sobald {app} ihn erreicht. | No connection to the server right now. The folder number appears once {app} reaches it. |
| `folder.menu.stop` | Auf diesem Gerät nicht mehr synchronisieren | Stop syncing on this device |
| `folder.stop.title` | „{folder}“ nicht mehr synchronisieren? | Stop syncing “{folder}”? |
| `folder.stop.body` | Die Dateien bleiben in diesem Ordner und auf deinem Server. Du kannst den Ordner später wieder hinzufügen. | The files stay in this folder and on your server. You can add the folder again later. |
| `folder.stop.confirm` | Nicht mehr synchronisieren | Stop syncing |
| `folder.menu.delete` | Auf allen Geräten löschen | Delete on all devices |
| `folder.delete.title` | „{folder}“ auf allen Geräten löschen? | Delete “{folder}” on all devices? |
| `folder.delete.body.one` | Der Ordner verschwindet von allen deinen Geräten. {days} Tag lang kannst du ihn unter Ordner hinzufügen zurückholen. | The folder disappears from all your devices. For {days} day you can bring it back under Add folder. |
| `folder.delete.body.other` | Der Ordner verschwindet von allen deinen Geräten. {days} Tage lang kannst du ihn unter Ordner hinzufügen zurückholen. | The folder disappears from all your devices. For {days} days you can bring it back under Add folder. |
| `folder.delete.confirm` | Überall löschen | Delete everywhere |
| `folder.deleted.section` | Gelöschte Ordner | Deleted folders |
| `folder.deleted.restore` | Zurückholen | Bring back |
| `folder.deleted.done` | „{folder}“ ist gelöscht. | “{folder}” has been deleted. |
| `activity.changed` | geändert | changed |
| `activity.added` | neu | new |
| `activity.deleted` | gelöscht | deleted |
| `activity.renamed` | umbenannt | renamed |
| `activity.fromDevice` | von {device} | from {device} |
| `activity.restored` | wiederhergestellt | restored |
| `activity.twoVersions` | zwei Fassungen | two versions |
| `activity.group.one` | {folder}: {count} neue Datei | {folder}: {count} new file |
| `activity.group.other` | {folder}: {count} neue Dateien | {folder}: {count} new files |
| `activity.remoteDeleted.one` | {folder}: {count} Datei auf {device} gelöscht | {folder}: {count} file deleted on {device} |
| `activity.remoteDeleted.other` | {folder}: {count} Dateien auf {device} gelöscht | {folder}: {count} files deleted on {device} |
| `activity.cameBack` | {name} ist wieder da, weil es auf {device} geändert wurde. | {name} is back because it was changed on {device}. |
| `common.cancel` | Abbrechen | Cancel |
| `common.close` | Schließen | Close |
| `common.undo` | Rückgängig | Undo |
| `common.retry` | Jetzt versuchen | Try now |
| `common.copyReport` | Fehlerbericht kopieren | Copy error report |
| `common.reportCopied` | Fehlerbericht kopiert. Schick ihn dem Betreiber deines Servers. | Error report copied. Send it to the person who runs your server. |
| `main.status.attention` | Sieh dir den Hinweis unten an. | Take a look at the notice below. |
| `main.addFolder.new` | Anderen Ordner wählen … | Choose another folder … |
| `main.addFolder.bring` | Hierher holen | Bring here |
| `main.rowMenu` | Aktionen für „{name}“ | Actions for “{name}” |
| `folder.reason.missing` | Ordner nicht gefunden | folder not found |
| `folder.reason.olderState` | älterer Stand auf dem Server | older state on the server |
| `folder.reason.removedHeads` | Änderungen eines entfernten Geräts | changes from a removed device |
| `folder.number.title` | Ordnernummer von „{folder}“ | Folder number of “{folder}” |
| `folder.number.body` | Vergleiche diese Zahlen mit der Ordnernummer auf deinem anderen Gerät. Sind sie gleich, sehen beide Geräte denselben Stand. | Compare these numbers with the folder number on your other device. If they are the same, both devices see the same state. |
| `folder.deleted.daysLeft.one` | noch {days} Tag | {days} day left |
| `folder.deleted.daysLeft.other` | noch {days} Tage | {days} days left |
| `common.undone` | Rückgängig gemacht. | Undone. |
| `common.save` | Speichern | Save |
| `common.saved` | Gespeichert: {path} | Saved: {path} |
| `common.loading` | Wird geladen … | Loading … |

### 13.6 Conflicts and names

| Key | de | en |
| --- | --- | --- |
| `conflict.notice` | {name} wurde auf zwei Geräten geändert. Beide Fassungen sind da. | {name} was changed on two devices. Both versions are there. |
| `conflict.noticeMany.one` | {count} Datei wurde auf zwei Geräten geändert. Beide Fassungen sind da. | {count} file was changed on two devices. Both versions are there. |
| `conflict.noticeMany.other` | {count} Dateien wurden auf zwei Geräten geändert. Beide Fassungen sind jeweils da. | {count} files were changed on two devices. Both versions of each are there. |
| `conflict.banner.one` | {count} Datei gibt es in zwei Fassungen | {count} file exists in two versions |
| `conflict.banner.other` | {count} Dateien gibt es in zwei Fassungen | {count} files exist in two versions |
| `conflict.view` | Ansehen | View |
| `conflict.version` | Fassung von {device}, {time} | Version from {device}, {time} |
| `conflict.versionSize` | {version}, {size} | {version}, {size} |
| `conflict.openBoth` | Beide öffnen | Open both |
| `conflict.keepThis` | Diese behalten | Keep this one |
| `conflict.keepBoth` | Beide behalten | Keep both |
| `conflict.keptThis.one` | Erledigt. Die andere Fassung findest du {days} Tag lang unter Frühere Versionen. | Done. You can find the other version under Earlier versions for {days} day. |
| `conflict.keptThis.other` | Erledigt. Die andere Fassung findest du {days} Tage lang unter Frühere Versionen. | Done. You can find the other version under Earlier versions for {days} days. |
| `conflict.fileWord` | Konflikt | conflict |
| `conflict.caseOnly` | Zwei Dateien unterscheiden sich nur in Groß- und Kleinschreibung. Windows kann sie nicht nebeneinander speichern. | Two files differ only in upper and lower case. Windows cannot store them side by side. |
| `names.banner.one` | {count} Datei kann auf diesem Gerät nicht gespeichert werden | {count} file cannot be stored on this device |
| `names.banner.other` | {count} Dateien können auf diesem Gerät nicht gespeichert werden | {count} files cannot be stored on this device |
| `names.from` | Von {device} | From {device} |
| `names.char` | Der Name enthält „{char}“. Das erlaubt Windows nicht. | The name contains “{char}”. Windows does not allow that. |
| `names.reserved` | „{name}“ ist unter Windows ein reservierter Name. | “{name}” is a reserved name on Windows. |
| `names.trailing` | Der Name endet mit einem Punkt oder Leerzeichen. Das erlaubt Windows nicht. | The name ends with a dot or a space. Windows does not allow that. |
| `names.control` | Der Name enthält ein unsichtbares Steuerzeichen. | The name contains an invisible control character. |
| `names.rename` | Umbenennen | Rename |
| `names.renameHelp` | Der neue Name gilt auf allen deinen Geräten. | The new name applies on all your devices. |
| `names.cannotCreate` | Das lässt sich hier nicht anlegen, weil an dieser Stelle schon eine Verknüpfung oder Systemdatei liegt. | This cannot be created here because a shortcut or system file is already in its place. |
| `names.notSynced.one` | {count} Eintrag wird nicht synchronisiert | {count} entry is not synced |
| `names.notSynced.other` | {count} Einträge werden nicht synchronisiert | {count} entries are not synced |
| `names.notSynced.link` | Verknüpfungen und Links werden nicht synchronisiert. | Shortcuts and links are not synced. |
| `names.notSynced.system` | Systemdateien werden nicht synchronisiert. | System files are not synced. |
| `names.ignore` | Ignorieren | Ignore |
| `names.ignoreHelp` | Die Datei bleibt auf deinen anderen Geräten und auf dem Server. | The file stays on your other devices and on the server. |
| `conflict.title` | Dateien in zwei Fassungen | Files in two versions |
| `conflict.keptBoth` | Erledigt. Beide Dateien bleiben, wie sie sind. | Done. Both files stay as they are. |
| `conflict.allDone` | Alles aufgeräumt. | All tidied up. |
| `names.title` | Dateien, die hier nicht gespeichert werden können | Files that cannot be stored here |
| `names.newName` | Neuer Name | New name |
| `names.renamed` | Umbenannt in „{name}“. | Renamed to “{name}”. |

### 13.7 Problems

| Key | de | en |
| --- | --- | --- |
| `deletes.title.one` | {count} Datei gelöscht | {count} file deleted |
| `deletes.title.other` | {count} Dateien gelöscht | {count} files deleted |
| `deletes.body.one` | In „{folder}“ wurde {count} Datei gelöscht. Soll sie auch auf deinen anderen Geräten verschwinden? | {count} file was deleted in “{folder}”. Should it disappear from your other devices too? |
| `deletes.body.other` | In „{folder}“ wurden {count} Dateien gelöscht. Sollen sie auch auf deinen anderen Geräten verschwinden? | {count} files were deleted in “{folder}”. Should they disappear from your other devices too? |
| `deletes.sample.one` | und {count} weitere | and {count} more |
| `deletes.sample.other` | und {count} weitere | and {count} more |
| `deletes.list` | Liste ansehen | Show list |
| `deletes.kept.one` | Im Papierkorb bleiben sie {days} Tag lang erhalten. | They stay in the trash for {days} day. |
| `deletes.kept.other` | Im Papierkorb bleiben sie {days} Tage lang erhalten. | They stay in the trash for {days} days. |
| `deletes.restore` | Wiederherstellen | Restore |
| `deletes.confirm` | Ja, löschen | Yes, delete |
| `deletes.restored.one` | {count} Datei ist wieder da. | {count} file is back. |
| `deletes.restored.other` | {count} Dateien sind wieder da. | {count} files are back. |
| `missing.title` | „{folder}“ ist nicht mehr da | “{folder}” is gone |
| `missing.body` | {app} hat den Ordner angehalten. Auf dem Server und auf deinen anderen Geräten ist nichts gelöscht. | {app} has paused the folder. Nothing was deleted on the server or on your other devices. |
| `missing.find` | Ordner suchen | Find folder |
| `missing.redownload` | Neu herunterladen | Download again |
| `missing.wrongFolder` | Das ist nicht der Ordner „{folder}“. Wähle den Ordner, in den du ihn verschoben hast. | That is not the folder “{folder}”. Choose the folder you moved it to. |
| `offline.noNetwork` | Offline. Deine Dateien sind hier, Änderungen gehen später raus. | Offline. Your files are here, changes go out later. |
| `offline.server` | Dein Server antwortet gerade nicht. {app} versucht es weiter. | Your server is not answering right now. {app} keeps trying. |
| `offline.serverLong` | Dein Server antwortet seit {since} nicht. Sag dem Betreiber Bescheid. | Your server has not answered since {since}. Let the operator know. |
| `server.identity` | Dein Server weist sich anders aus als sonst. Zu deiner Sicherheit verbindet {app} nicht. Frag den Betreiber, ob er etwas geändert hat. | Your server identifies itself differently than usual. To keep you safe, {app} does not connect. Ask the operator whether they changed something. |
| `server.fix.scan` | Code von einem anderen Gerät scannen | Scan a code from another device |
| `server.fix.scanBody` | Öffne {app} auf einem Gerät, das noch verbindet, und wähle dort Geräte und dann Gerät hinzufügen. Scanne den Code oder füge den Link hier ein. | Open {app} on a device that still connects and choose Devices, then Add device. Scan the code or paste the link here. |
| `server.fix.done` | Verbunden. Alles läuft wieder. | Connected. Everything is running again. |
| `server.fix.compare` | Mit dem Betreiber vergleichen | Compare with the operator |
| `server.fix.compareTitle` | Servernummer vergleichen | Compare the server number |
| `server.fix.compareBody` | Bitte den Betreiber, auf dem Server diesen Befehl auszuführen: {command}. Stimmen alle Zahlen mit diesen hier überein? | Ask the operator to run this command on the server: {command}. Do all the numbers match these? |
| `server.fix.yes` | Ja, gleiche Zahlen, verbinden | Yes, same numbers, connect |
| `server.fix.no` | Nein, nicht verbinden | No, do not connect |
| `server.fix.mismatch` | Dann verbinde nicht. Sag dem Betreiber, dass die Zahlen nicht passen. Deine Dateien hier bleiben, wie sie sind. | Then do not connect. Tell the operator that the numbers do not match. Your files here stay as they are. |
| `server.number.label` | Servernummer | Server number |
| `quota.title` | Dein Speicher auf dem Server ist voll | Your storage on the server is full |
| `quota.body` | Neue Änderungen bleiben auf diesem Gerät, bis wieder Platz ist. Lösch Dateien, die du nicht mehr brauchst, oder frag den Betreiber nach mehr Platz. Frühere Versionen und der Papierkorb zählen nicht mit. | New changes stay on this device until there is room again. Delete files you no longer need, or ask the operator for more space. Earlier versions and the trash do not count. |
| `quotaFull.title` | Dein Speicher auf dem Server ist ganz voll | Your storage on the server is completely full |
| `quotaFull.body` | Auch Löschen geht gerade nicht mehr, weil dafür kein Platz frei ist. Nur der Betreiber kann jetzt Platz schaffen. Schick ihm den Fehlerbericht. Deine Dateien hier bleiben, wie sie sind. | Even deleting does not work right now, because there is no room left for it. Only the operator can make room now. Send them the error report. Your files here stay as they are. |
| `budget.line.one` | {count} Datei wartet, weil heute schon sehr viel hochgeladen wurde. Die Datei geht spätestens morgen raus. | {count} file is waiting because a lot was uploaded today. It goes out by tomorrow at the latest. |
| `budget.line.other` | {count} Dateien warten, weil heute schon sehr viel hochgeladen wurde. Die Dateien gehen spätestens morgen raus. | {count} files are waiting because a lot was uploaded today. They go out by tomorrow at the latest. |
| `notice.retained` | Alte Versionen belegen auf deinem Server gerade viel Platz. Der Betreiber weiß Bescheid. Du musst nichts tun. | Old versions take up a lot of space on your server right now. The operator has been told. You do not need to do anything. |
| `notice.budgetDevice` | „{device}“ hat heute sehr viel hochgeladen. Warst du das nicht, schau unter Geräte nach. | “{device}” uploaded a lot today. If that was not you, check under Devices. |
| `notice.minCount.one` | Dein Server hebt alte Versionen jetzt nur noch {days} Tag auf, auch in Ordnern, die sich selten ändern. Der Betreiber weiß Bescheid. | Your server now keeps old versions for {days} day only, also in folders that rarely change. The operator has been told. |
| `notice.minCount.other` | Dein Server hebt alte Versionen jetzt nur noch {days} Tage auf, auch in Ordnern, die sich selten ändern. Der Betreiber weiß Bescheid. | Your server now keeps old versions for {days} days only, also in folders that rarely change. The operator has been told. |
| `serverDisk.title` | Dein Server hat keinen Platz mehr | Your server is out of space |
| `serverDisk.body` | Neue Änderungen bleiben auf diesem Gerät, bis der Server wieder Platz hat. Das kann nur der Betreiber lösen. Sag ihm Bescheid. | New changes stay on this device until the server has room again. Only the operator can fix this. Let them know. |
| `disk.title` | Auf diesem Computer ist der Speicher voll | This computer’s disk is full |
| `disk.body` | {app} lädt weiter herunter, sobald wieder {size} frei sind. | {app} continues downloading once {size} are free again. |
| `disk.open` | Speicher anzeigen | Show storage |
| `older.title` | „{folder}“ ist angehalten | “{folder}” is paused |
| `older.body` | Dein Server zeigt einen älteren Stand, als dieses Gerät schon kannte. Meist hat der Betreiber eine Sicherung zurückgespielt. Deine Dateien hier sind sicher. | Your server shows an older state than this device already knew. Usually the operator has restored a backup. Your files here are safe. |
| `older.resume` | Fortsetzen … | Continue … |
| `older.check` | Jetzt noch mal prüfen | Check again now |
| `older.localOk` | Du kannst in diesem Ordner weiterarbeiten. Deine Änderungen gehen raus, sobald du fortsetzt oder der Server wieder den neueren Stand zeigt. | You can keep working in this folder. Your changes go out once you continue or the server shows the newer state again. |
| `older.compare.title` | Erst mit einem anderen Gerät vergleichen | First compare with another device |
| `older.compare.body` | Öffne {app} auf einem anderen Gerät und wähle beim Ordner „{folder}“ Ordnernummer anzeigen. Stimmen die Zahlen mit diesen hier überein? | Open {app} on another device and choose Show folder number for “{folder}”. Do the numbers match these? |
| `older.compare.yes` | Ja, gleiche Zahlen | Yes, same numbers |
| `older.compare.no` | Nein, sie sind anders | No, they are different |
| `older.noDevice` | Kein anderes Gerät da? | No other device? |
| `older.confirm.title` | „{folder}“ fortsetzen? | Continue “{folder}”? |
| `older.confirm.merge` | Deine Dateien auf diesem Gerät werden mit dem Stand auf dem Server zusammengeführt. Weicht eine Datei ab, bleiben beide Fassungen erhalten. | The files on this device are merged with the state on the server. If a file differs, both versions are kept. |
| `older.confirm.loss` | Frühere Versionen aus der Zeit nach der Sicherung gehen dabei verloren. Was nur in solchen Zwischenständen war, ist danach nicht mehr da. | Earlier versions from the time after the backup are lost. Whatever existed only in those in-between states is gone afterwards. |
| `older.confirm.go` | Fortsetzen | Continue |
| `older.blind.title` | Ohne Vergleich fortsetzen? | Continue without comparing? |
| `older.blind.body` | Ohne zweites Gerät kann {app} nicht prüfen, ob dein Server wirklich nur eine Sicherung zurückgespielt hat. Mach das nur, wenn der Betreiber es dir bestätigt hat. | Without a second device, {app} cannot check whether your server really only restored a backup. Only do this if the operator has confirmed it to you. |
| `older.blind.go` | Ohne Vergleich fortsetzen | Continue without comparing |
| `older.mismatch.title` | Dann setze nicht fort | Then do not continue |
| `older.mismatch.body` | Deine Geräte sehen gerade nicht denselben Stand deines Servers. Sag dem Betreiber Bescheid und schick ihm den Fehlerbericht. Deine Dateien hier bleiben, wie sie sind. | Your devices do not see the same state of your server right now. Let the operator know and send them the error report. Your files here stay as they are. |
| `older.done` | „{folder}“ läuft wieder. | “{folder}” is running again. |
| `older.donePerDevice` | Ist der Ordner auf einem anderen Gerät auch angehalten, bestätige es dort genauso. | If the folder is paused on another device too, confirm there the same way. |
| `freeze.line.one` | Seit {days} Tag nichts Neues von deinen anderen Geräten. Wenn du dort etwas geändert hast, vergleiche die Ordnernummer. | Nothing new from your other devices for {days} day. If you changed something there, compare the folder number. |
| `freeze.line.other` | Seit {days} Tagen nichts Neues von deinen anderen Geräten. Wenn du dort etwas geändert hast, vergleiche die Ordnernummer. | Nothing new from your other devices for {days} days. If you changed something there, compare the folder number. |
| `freeze.compare` | Ordnernummer vergleichen | Compare folder number |
| `freeze.compareBody` | Öffne diesen Ordner auf einem anderen Gerät und vergleiche die Zahlen. Sind sie gleich, ist alles in Ordnung. | Open this folder on another device and compare the numbers. If they are the same, everything is fine. |
| `removed.body` | Dieses Gerät wurde von „{device}“ entfernt. Deine Dateien bleiben hier, werden aber nicht mehr synchronisiert. | This device was removed by “{device}”. Your files stay here but no longer sync. |
| `removed.repair` | Wieder koppeln | Pair again |
| `removed.notMe` | Das war ich nicht | That was not me |
| `removed.notMeBody` | Dann hat jemand Zugriff auf eines deiner Geräte. Richte {app} mit deinem Wiederherstellungsblatt neu ein und entferne dabei die Geräte, die du nicht kennst. | Then someone has access to one of your devices. Set up {app} again with your recovery sheet and remove the devices you do not recognize. |
| `update.body` | {app} braucht ein Update, um weiter zu synchronisieren. | {app} needs an update to keep syncing. |
| `update.now` | Jetzt aktualisieren | Update now |
| `update.bodyManual` | {app} braucht ein Update, um weiter zu synchronisieren. Installiere die neue Version, dann geht es von selbst weiter. | {app} needs an update to keep syncing. Install the new version and it carries on by itself. |
| `update.upToDate` | Es gibt noch keine neuere Version. Versuch es später noch einmal. | There is no newer version yet. Try again later. |
| `update.installed` | Version {version} ist installiert. Starte {app} neu, falls es nicht von selbst neu startet. | Version {version} is installed. Restart {app} if it does not restart by itself. |
| `refused.body` | Dein Server lässt dieses Gerät nicht mehr herein. | Your server no longer lets this device in. |
| `deletes.decide` | Entscheiden | Decide |
| `deletes.done.one` | {count} Datei ist jetzt auch auf deinen anderen Geräten gelöscht. | {count} file is now deleted on your other devices too. |
| `deletes.done.other` | {count} Dateien sind jetzt auch auf deinen anderen Geräten gelöscht. | {count} files are now deleted on your other devices too. |
| `heads.title` | Änderungen von einem entfernten Gerät | Changes from a removed device |
| `heads.body` | In „{folder}“ sind Änderungen von „{device}“ angekommen, obwohl das Gerät nicht mehr zu deinem Konto gehört. | Changes from “{device}” arrived in “{folder}”, although that device no longer belongs to your account. |
| `heads.bodyMany.one` | In „{folder}“ sind Änderungen von {count} Gerät angekommen, das nicht mehr zu deinem Konto gehört. | Changes from {count} device that no longer belongs to your account arrived in “{folder}”. |
| `heads.bodyMany.other` | In „{folder}“ sind Änderungen von {count} Geräten angekommen, die nicht mehr zu deinem Konto gehören. | Changes from {count} devices that no longer belong to your account arrived in “{folder}”. |
| `heads.advice` | Am sichersten machst du sie rückgängig. Bis du dich entscheidest, wartet der Ordner. | Undoing them is the safest choice. Until you decide, the folder waits. |
| `heads.undo` | Ansehen und rückgängig machen | Review and undo |
| `heads.accept` | Übernehmen | Accept |
| `heads.accepted` | Übernommen. „{folder}“ wird wieder synchronisiert. | Accepted. “{folder}” syncs again. |
| `heads.undoLater` | Doch rückgängig machen | Undo after all |
| `removedHeads.title` (notification, backend) | Änderungen des entfernten Geräts „{device}“ in „{folder}“ | Changes from the removed device “{device}” in “{folder}” |
| `server.fix.apply` | Verbinden | Connect |
| `older.stillOlder` | Der Server zeigt noch den älteren Stand. | The server still shows the older state. |

### 13.8 Restore

| Key | de | en |
| --- | --- | --- |
| `restore.title` | Frühere Versionen von „{folder}“ | Earlier versions of “{folder}” |
| `restore.tab.versions` | Versionen | Versions |
| `restore.tab.trash` | Papierkorb | Trash |
| `restore.today` | Heute | Today |
| `restore.yesterday` | Gestern | Yesterday |
| `restore.entry` | {time} {device} | {time} {device} |
| `restore.entry.changed.one` | {count} Datei geändert | {count} file changed |
| `restore.entry.changed.other` | {count} Dateien geändert | {count} files changed |
| `restore.entry.added.one` | {count} Datei neu | {count} new file |
| `restore.entry.added.other` | {count} Dateien neu | {count} new files |
| `restore.entry.deleted.one` | {count} Datei gelöscht | {count} file deleted |
| `restore.entry.deleted.other` | {count} Dateien gelöscht | {count} files deleted |
| `restore.stateOf` | Stand von {when} | State of {when} |
| `restore.diff` | Gegenüber jetzt: {changed}, {missing} | Compared to now: {changed}, {missing} |
| `restore.diffSingle` | Gegenüber jetzt: {part} | Compared to now: {part} |
| `restore.diff.changed.one` | {count} Datei anders | {count} file different |
| `restore.diff.changed.other` | {count} Dateien anders | {count} files different |
| `restore.diff.missing.one` | {count} Datei fehlt jetzt | {count} file missing now |
| `restore.diff.missing.other` | {count} Dateien fehlen jetzt | {count} files missing now |
| `restore.onlyDiff` | Nur Unterschiede | Only differences |
| `restore.file.different` | anders | different |
| `restore.file.missing` | fehlt jetzt | missing now |
| `restore.file.newer` | neu seitdem | new since |
| `restore.file.restore` | Wiederherstellen | Restore |
| `restore.file.copy` | Als Kopie speichern | Save as copy |
| `restore.file.history` | Alle Versionen dieser Datei | All versions of this file |
| `restore.file.done` | Wiederhergestellt. Die vorherige Fassung ist unter Frühere Versionen. | Restored. The previous version is under Earlier versions. |
| `restore.file.doneRenamed` | Wiederhergestellt als „{name}“, weil der Name schon vergeben war. | Restored as “{name}” because the name was taken. |
| `restore.file.waiting` | Wartet | Waiting |
| `restore.waitBudget` | Wartet: Heute wurde schon sehr viel hochgeladen. Das Wiederherstellen läuft von selbst, spätestens morgen. | Waiting: a lot was uploaded today already. The restore runs by itself, by tomorrow at the latest. |
| `restore.noSpace` | Dafür ist auf deinem Server kein Platz. Lösch Dateien, die du nicht mehr brauchst, oder frag den Betreiber nach mehr Platz. Es wurde nichts verändert. | There is no room for this on your server. Delete files you no longer need, or ask the operator for more space. Nothing was changed. |
| `restore.expired` | Diese Version ist nicht mehr verfügbar. Es wurde nichts verändert. | This version is no longer available. Nothing was changed. |
| `restore.expiredOlder.one` | {count} ältere Version ist nicht mehr verfügbar | {count} older version is no longer available |
| `restore.expiredOlder.other` | {count} ältere Versionen sind nicht mehr verfügbar | {count} older versions are no longer available |
| `restore.reanchored` | Hier hat dein Server einen älteren Stand zurückgespielt. Zwischenstände von davor fehlen. | Here your server went back to an older state. Some in-between versions from before are missing. |
| `restore.fileWord` | wiederhergestellt | restored |
| `restore.beforeDevice.device` | Gerät | Device |
| `restore.beforeDevice.from` | ab | from |
| `restore.beforeDevice.advice` | Entferne dieses Gerät zuerst, sonst ändert es die Dateien gleich wieder. | Remove this device first, or it will change the files again right away. |
| `restore.folder` | Ganzen Ordner auf diesen Stand zurücksetzen | Reset the whole folder to this state |
| `restore.folder.title` | Auf diesen Stand zurücksetzen? | Reset to this state? |
| `restore.folder.body` | „{folder}“ wird auf den Stand von {when} zurückgesetzt. Der jetzige Stand bleibt als Version erhalten, du kannst also auch das rückgängig machen. | “{folder}” will be reset to the state of {when}. The current state stays as a version, so you can undo this too. |
| `restore.folder.confirm` | Zurücksetzen | Reset |
| `restore.folder.done` | „{folder}“ ist auf dem Stand von {when}. | “{folder}” is back to the state of {when}. |
| `restore.retention.one` | Versionen bleiben {days} Tag erhalten. Das legt dein Server fest. | Versions are kept for {days} day. Your server sets this. |
| `restore.retention.other` | Versionen bleiben {days} Tage erhalten. Das legt dein Server fest. | Versions are kept for {days} days. Your server sets this. |
| `restore.otherVersion` | Andere Version wählen | Choose another version |
| `restore.beforeDevice` | Stand vor Änderungen von … | State before changes from … |
| `restore.beforeDeviceEntry` | Vor den Änderungen von „{device}“ | Before the changes from “{device}” |
| `restore.beforeDevice.finding` | Wird gesucht … | Searching … |
| `trash.title` | Papierkorb von „{folder}“ | Trash of “{folder}” |
| `trash.search` | Suchen | Search |
| `trash.deleted` | gelöscht {when}, {device} | deleted {when}, {device} |
| `trash.restore` | Wiederherstellen | Restore |
| `trash.restored.one` | {count} Datei wiederhergestellt | {count} file restored |
| `trash.restored.other` | {count} Dateien wiederhergestellt | {count} files restored |
| `trash.info.one` | Gelöschte Dateien bleiben {days} Tag, dann entfernt dein Server sie. Endgültig löschen kann nur der Betreiber. | Deleted files stay for {days} day, then your server removes them. Only the operator can delete them for good. |
| `trash.info.other` | Gelöschte Dateien bleiben {days} Tage, dann entfernt dein Server sie. Endgültig löschen kann nur der Betreiber. | Deleted files stay for {days} days, then your server removes them. Only the operator can delete them for good. |
| `trash.empty` | Der Papierkorb ist leer. | The trash is empty. |
| `suspect.title` | Auf „{device}“ wurden sehr viele Dateien verändert | Very many files were changed on “{device}” |
| `suspect.body.one` | Das kann ein Schadprogramm sein. Der Stand davor ist gesichert und bleibt mindestens {days} Tag erhalten. | This may be malware. The state before is saved and kept for at least {days} day. |
| `suspect.body.other` | Das kann ein Schadprogramm sein. Der Stand davor ist gesichert und bleibt mindestens {days} Tage erhalten. | This may be malware. The state before is saved and kept for at least {days} days. |
| `suspect.what` | Was jetzt? | What now? |
| `suspect.me` | Das war ich | That was me |
| `suspect.meDone` | Ausgeblendet auf diesem Gerät. Auf deinen anderen Geräten siehst du den Hinweis noch. | Hidden on this device. Your other devices still show the notice. |
| `suspect.step1` | Trenne „{device}“ vom Netz oder entferne es hier. | Disconnect “{device}” from the network or remove it here. |
| `suspect.step2` | Prüfe das Gerät mit deinem Virenschutz. | Check that device with your antivirus. |
| `suspect.step3` | Hol den Stand von davor zurück. | Bring back the state from before. |
| `suspect.view` | Stand vor den Änderungen ansehen | View the state before the changes |
| `restore.list` | Versionen, neueste zuerst | Versions, newest first |
| `restore.whenToday` | heute, {time} | today, {time} |
| `restore.whenYesterday` | gestern, {time} | yesterday, {time} |
| `restore.whenDate` | {date}, {time} | {date}, {time} |
| `restore.diffNone` | Gegenüber jetzt: keine Unterschiede | Compared to now: no differences |
| `restore.file.historyOf` | Nur Versionen von „{name}“ | Only versions of “{name}” |
| `restore.file.historyAll` | Alle Versionen zeigen | Show all versions |
| `restore.file.copied` | Gespeichert als „{name}“. | Saved as “{name}”. |
| `restore.none` | Noch keine früheren Versionen. | No earlier versions yet. |
| `restore.noDiff` | Keine Unterschiede zu jetzt. | No differences to now. |
| `restore.beforeDevice.find` | Stand suchen | Find state |
| `restore.beforeDevice.none` | In dieser Zeit hat das Gerät hier nichts geändert. | That device changed nothing here in that time. |
| `trash.restoreSelected.one` | {count} Datei wiederherstellen | Restore {count} file |
| `trash.restoreSelected.other` | {count} Dateien wiederherstellen | Restore {count} files |
| `trash.select` | „{name}“ auswählen | Select “{name}” |
| `trash.noMatch` | Nichts gefunden für „{query}“. | Nothing found for “{query}”. |

### 13.9 Devices

| Key | de | en |
| --- | --- | --- |
| `devices.title` | Deine Geräte | Your devices |
| `devices.add` | Gerät hinzufügen | Add device |
| `devices.this` | Dieses Gerät | This device |
| `devices.lastSeen` | zuletzt {when} | last seen {when} |
| `devices.since` | seit {date} | since {date} |
| `devices.stale` | Lange nicht gesehen. Entferne es, wenn du es nicht mehr hast. | Not seen for a long time. Remove it if you no longer have it. |
| `devices.rename` | Umbenennen | Rename |
| `devices.showSafety` | Sicherheitsnummer anzeigen | Show safety number |
| `devices.remove` | Entfernen | Remove |
| `devices.remove.title` | „{device}“ entfernen? | Remove “{device}”? |
| `devices.remove.body` | Danach kann dieses Gerät nichts mehr synchronisieren und keine neuen Dateien mehr lesen. Was schon darauf liegt, bleibt dort: {app} kann auf einem anderen Gerät nichts aus der Ferne löschen. | After that, this device can no longer sync or read new files. What is already on it stays there: {app} cannot delete anything remotely. |
| `devices.remove.lost` | Verloren oder gestohlen? Dann entferne es jetzt. | Lost or stolen? Then remove it now. |
| `devices.removed` | „{device}“ wurde entfernt. | “{device}” was removed. |
| `devices.removedBy` | „{device}“ wurde von „{by}“ entfernt. | “{device}” was removed by “{by}”. |
| `devices.addedBy` | „{device}“ wurde hinzugefügt. | “{device}” was added. |
| `devices.disconnect` | Dieses Gerät trennen | Disconnect this device |
| `devices.disconnect.body` | Deine Dateien bleiben in den Ordnern, werden aber nicht mehr synchronisiert. Du kannst das Gerät später wieder koppeln. | Your files stay in the folders but no longer sync. You can pair this device again later. |
| `devices.lastOne` | Das ist dein einziges Gerät. Ohne Gerät kommst du nur noch mit dem Wiederherstellungscode an deine Dateien. | This is your only device. Without a device, only your recovery code can get you to your files. |
| `devices.lastOne.confirm` | Trotzdem trennen | Disconnect anyway |
| `devices.recovery` | Wiederherstellungscode | Recovery code |
| `devices.recovery.created` | erstellt am {date} | created on {date} |
| `devices.recovery.renew` | Neu erzeugen | Create new |
| `devices.recovery.renewBody` | Der neue Code ersetzt den alten. Der alte funktioniert danach nicht mehr. Wirf das alte Blatt weg. | The new code replaces the old one. The old one stops working. Throw the old sheet away. |
| `devices.rename.title` | „{device}“ umbenennen | Rename “{device}” |
| `devices.rename.label` | Name | Name |
| `devices.safety.title` | Sicherheitsnummer von „{device}“ | Safety number of “{device}” |
| `devices.safety.body` | Auf dem Gerät selbst steht dieselbe Zahlenreihe unter Geräte, Dieses Gerät. | The device itself shows the same numbers under Devices, This device. |
| `devices.recovery.renewed` | Neuer Code gilt. Der alte funktioniert nicht mehr. | The new code is active. The old one no longer works. |

### 13.10 Settings

| Key | de | en |
| --- | --- | --- |
| `settings.title` | Einstellungen | Settings |
| `settings.autostart` | Beim Anmelden starten | Start at sign-in |
| `settings.autostartHelp` | Dann bleiben deine Ordner aktuell, ohne dass du daran denken musst. | Keeps your folders up to date without you having to think of it. |
| `settings.language` | Sprache | Language |
| `settings.languageSystem` | Wie das System | Same as system |
| `settings.account` | Konto | Account |
| `settings.server` | Server: {host} | Server: {host} |
| `settings.retention.one` | Versionen bleiben {days} Tag erhalten. | Versions are kept for {days} day. |
| `settings.retention.other` | Versionen bleiben {days} Tage erhalten. | Versions are kept for {days} days. |
| `settings.about` | Über {app} | About {app} |
| `settings.version` | Version {version} | Version {version} |
| `settings.saveReport` | Fehlerbericht speichern | Save error report |
| `settings.reportHelp` | Enthält Versionen, Zustände und Fehlercodes. Keine Dateinamen, keine Inhalte, keine Schlüssel. | Contains versions, states and error codes. No file names, no contents, no keys. |
| `settings.localNote` | Deine Dateien liegen auf diesem Computer unverschlüsselt. Schalte die Laufwerksverschlüsselung deines Systems ein. | Your files are stored unencrypted on this computer. Turn on your system’s drive encryption. |
| `settings.serverNote` | Auf dem Server sind deine Dateien verschlüsselt. Der Betreiber sieht weder Namen noch Inhalte. | On the server your files are encrypted. The operator sees neither names nor contents. |
| `settings.reportPreview` | Das steht im Fehlerbericht | What the error report contains |
| `reset.action` | Dieses Gerät zurücksetzen | Reset this device |
| `reset.help` | Für einen Neuanfang: {app} vergisst dein Konto auf diesem Gerät. Deine Dateien bleiben hier. | To start over: {app} forgets your account on this device. Your files stay here. |
| `reset.question` | Dieses Gerät wirklich zurücksetzen? | Really reset this device? |
| `reset.body` | {app} hört hier auf zu synchronisieren und vergisst das Konto. Danach kannst du ein neues Konto einrichten oder dieses Gerät wieder hinzufügen. | {app} stops syncing here and forgets the account. Afterwards you can set up a new account or add this device again. |
| `reset.confirm` | Zurücksetzen | Reset |
| `help.title` | Hilfe | Help |
| `help.body` | {app} hält deine Ordner auf allen deinen Geräten gleich. Wenn etwas deine Entscheidung braucht, steht es oben im Fenster. | {app} keeps your folders the same on all your devices. When something needs your decision, it shows at the top of the window. |
| `help.keys` | Tastenkürzel | Keyboard shortcuts |
| `help.key.help` | Diese Hilfe öffnen | Open this help |
| `help.key.settings` | Einstellungen öffnen | Open settings |
| `help.key.devices` | Geräte öffnen | Open devices |
| `help.key.close` | Dialog schließen | Close a dialog |
| `help.key.menu` | Aktionen einer Zeile öffnen | Open the actions of a row |
| `keys.ctrl` | Strg | Ctrl |
| `keys.shift` | Umschalt | Shift |
| `keys.alt` | Alt | Alt |
| `keys.escape` | Esc | Esc |

### 13.11 Error texts

Each says what happened and what to do; the technical cause goes into the error report.

| Key | de | en |
| --- | --- | --- |
| `error.invite.notALink` | Das ist kein Einladungslink. Er beginnt mit https:// und enthält ein #. | That is not an invite link. It starts with https:// and contains a #. |
| `error.invite.used` | Diese Einladung wurde schon benutzt. Bitte den Betreiber um eine neue. | This invite has already been used. Ask the operator for a new one. |
| `error.invite.expired` | Diese Einladung ist abgelaufen. Bitte den Betreiber um eine neue. | This invite has expired. Ask the operator for a new one. |
| `error.invite.unreachable` | Der Server aus dem Link antwortet nicht. Prüfe deine Internetverbindung oder frag den Betreiber. | The server in the link does not answer. Check your internet connection or ask the operator. |
| `error.insecure` | Dieser Server ist nicht verschlüsselt erreichbar. {app} verbindet sich nur über https. | This server cannot be reached securely. {app} only connects over https. |
| `error.pair.notALink` | Das ist kein Kopplungslink. Kopiere ihn auf dem anderen Gerät unter Geräte und dann Gerät hinzufügen. | That is not a pairing link. Copy it on the other device under Devices, then Add device. |
| `error.link.damaged` | Der Link ist unvollständig. Kopiere ihn noch einmal ganz. | The link is incomplete. Copy all of it again. |
| `error.recover.notALink` | Das ist nicht der Link von deinem Blatt. Er beginnt mit hangar-drive://recover#. | That is not the link from your sheet. It starts with hangar-drive://recover#. |
| `error.pair.expired` | Dieser Code ist abgelaufen oder wurde schon benutzt. Erzeuge auf dem anderen Gerät einen neuen. | This code has expired or was already used. Create a new one on the other device. |
| `error.pair.typo` | Im Code ist ein Tippfehler. Vergleiche ihn Zeichen für Zeichen. | There is a typo in the code. Compare it character by character. |
| `error.pair.declined` | Das andere Gerät hat abgelehnt. Starte noch mal, wenn das ein Versehen war. | The other device declined. Start again if that was a mistake. |
| `error.pair.tooMany` | Zu viele Versuche. Warte ein paar Minuten und versuch es dann noch mal. | Too many attempts. Wait a few minutes, then try again. |
| `error.server.otherAccount` | Dieser Code gehört zu einem anderen Konto. Nimm einen Code von einem deiner eigenen Geräte. | This code belongs to a different account. Use a code from one of your own devices. |
| `error.recovery.typo` | Im Code ist ein Tippfehler. Vergleiche ihn Gruppe für Gruppe mit deinem Blatt. | There is a typo in the code. Compare it group by group with your sheet. |
| `error.recovery.unknown` | Dieser Code gehört zu keinem Konto auf diesem Server. Prüfe die Serveradresse auf deinem Blatt. | This code does not belong to any account on this server. Check the server address on your sheet. |
| `error.recovery.used` | Dieser Code wurde ersetzt. Nimm das neuere Blatt. | This code was replaced. Use the newer sheet. |
| `error.recovery.otherApp` | Das ist ein Code für Hangar. Hier gehört der Code für {app} hin. | That is a code for Hangar. This needs the code for {app}. |
| `error.recovery.savedInSync` | Speichere den Code nicht in einem synchronisierten Ordner, sonst liegt er neben den Dateien, die er öffnet. Wähle einen anderen Ort. | Do not save the code in a synced folder, or it sits next to the files it opens. Choose another place. |
| `error.recovery.savedInCloud` | Dieser Ordner wird mit einer Cloud synchronisiert. Speichere das Blatt lieber an einem Ort, der nur auf diesem Gerät liegt, zum Beispiel in „Downloads“ oder auf einem USB-Stick. | This folder syncs with a cloud. Better save the sheet somewhere that stays on this device only, for example in “Downloads” or on a USB stick. |
| `error.folder.network` | Netzlaufwerke gehen nicht. Wähle einen Ordner auf diesem Computer. | Network drives do not work. Choose a folder on this computer. |
| `error.folder.root` | Ein ganzes Laufwerk geht nicht. Wähle einen Ordner darauf. | A whole drive does not work. Choose a folder on it. |
| `error.folder.system` | Dieser Ordner gehört zum System. Wähle einen eigenen Ordner. | This folder belongs to the system. Choose a folder of your own. |
| `error.folder.nested` | Dieser Ordner liegt in „{folder}“ oder enthält ihn. Wähle einen Ordner daneben. | This folder is inside “{folder}” or contains it. Choose a folder next to it. |
| `error.folder.noAccess` | {app} darf in diesen Ordner nicht schreiben. Wähle einen anderen. | {app} is not allowed to write to this folder. Choose another one. |
| `error.rename.invalid` | Auch dieser Name geht unter Windows nicht. | This name does not work on Windows either. |
| `error.rename.exists` | Eine Datei mit diesem Namen gibt es dort schon. | A file with this name already exists there. |
| `error.restore.failed` | Das Wiederherstellen hat nicht geklappt. Prüfe die Verbindung und versuch es noch mal. Es wurde nichts verändert. | Restoring did not work. Check the connection and try again. Nothing was changed. |
| `error.locked` | {name} ist gerade in einem anderen Programm geöffnet. {app} versucht es gleich wieder. | {name} is open in another program right now. {app} will try again shortly. |
| `error.busy` | Gerade beschäftigt. Versuch es gleich noch mal. | Busy right now. Try again in a moment. |
| `error.unexpected` | Etwas ist schiefgegangen. Deine Dateien sind nicht betroffen. Speichere einen Fehlerbericht unter Einstellungen. | Something went wrong. Your files are not affected. Save an error report under Settings. |
| `error.server.unreachable` | Der Server antwortet nicht. Prüfe deine Internetverbindung oder frag den Betreiber. | The server does not answer. Check your internet connection or ask the operator. |
| `error.rename.empty` | Gib einen Namen ein. | Enter a name. |
| `error.notReady` | Das kann diese Version von {app} noch nicht. | This version of {app} cannot do that yet. |

## 14. Open questions

All seven were decided on 2026-11-26; see "Decisions on the open questions" at the end. Items 2
and 3 now follow the rules of [[0001-foundation]] sections 4 and 6.

1. **Conflict file name language** (7.1): localize the word "conflict" per creating device, which
   needs an ADR amendment, or keep the English word everywhere.
2. **Pin rotation** for self-signed servers (8.3).
3. **Recovery from a legitimately restored server backup** (8.6).
4. **Deleting a folder everywhere** (6.3) is one row menu item away. Should it need a second
   step (typing the folder name), or is the {days} day way back enough?
5. **Re-encrypt after device removal** [ADR 4] has no UI in this concept. Proposal: leave it out
   of version 1, or offer it later as a folder action for the stolen device case.
6. **Metered networks**: pause large uploads automatically on metered connections, without a
   setting?
7. **Explorer integration** (navigation pane, context menu, overlay icons): which of these are
   feasible without package identity (marked unverified above).

## 15. Handover

**To the sync core and protocol (Backend):**

- Invite redemption only after the recovery code check, atomic with the first device entry and
  the recovery device (4.2.1).
- `hangar-drive://join` and `hangar-drive://pair` link handlers; a static `/join` page on the
  server that never sends the fragment to the server.
- ~~Account lookup by the recovery device's public key~~: decided otherwise, the account ID
  travels in the sheet's link (4.4). The app shell needs `inspectLink`, `acceptRemovedHeads`,
  the sheet document for printing and saving, and the `openLink` and `removedHeads` events,
  holding a start link until the window listens (`src/backend/types.ts`).
- A distinct version byte for Drive recovery codes, proposal prefix `D` (4.2 step 2).
- Per-account used storage, quota and retention days readable by the client (6.3, 9.1).
- What the timeline needs per commit (9.1): the writing device (from the signed commit body), the
  server time (kept until the tree expires, [ADR 5]), the counts of changed, added and deleted
  files, which the client computes by comparing the commit's tree with its first parent's,
  because a commit has no encrypted part [ADR 4 "Re-anchor mark"], and a fast "tree at commit"
  query.
- The anomaly pin as an event with the suspect device and the first commit of the burst (9.4).
  "Das war ich" is stored only on this device [ADR 5 "No shared dismissal"].
- The join of [ADR 3 "Joining a non-empty local folder"], plus a quick count of the local files
  before it starts (6.5).
- The re-anchor of [ADR 4] as a sync core flow with the confirmation from the UI, and the
  re-anchor bit of the commit `flags` [ADR 4 "Re-anchor mark"] read for the timeline (8.6, 9.1).
- The folder number of the server's current head on a paused device, and of the frontier on a
  running one after one check with the server, behind one call (8.6).
- The exact server CLI command that prints the server key number, passed to the UI as
  `{command}` (8.3).
- Which pending files wait for the upload budget, so the status can count them (6.1, 8.4); a
  pending restore job that runs once the budget allows and can be cancelled (9.1).
- Telling a refused delete at full headroom apart from a refused upload at full quota (8.4).
- Feed `notice` kinds with the parameters the texts need: device for a budget notice, days for
  the minimum count cap (8.4).
- A "last seen" time per device (10.1).
- Recycle bin for incoming deletions (8.1).
- Hysteresis and state aggregation for the tray (6.1) belong in the domain layer as an explicit
  state enum with transitions and tests [project rules], not in React.

**To `hangar-security`:** the recovery file save rules (4.2 step 2), the clipboard clearing, the
error report content (no names, no keys), the typed pairing path (4.3), which must always force
the safety number comparison, the optional comparison on the link and QR path (section 5), the
1 s arm delay on every confirm button of a number check (5, 8.3, 8.6), and the wording of the
re-anchor without comparison (8.6).

**To `hangar-frontend`:** the remaining ten languages for every key in section 13, with every
plural category each language reports (section 13, "Plural forms"), and the `--warn` on
`--panel` contrast fix in light mode (section 12).

## Decisions on the open questions (2026-11-26)

Taken by the lead agent so that building can start; each one can be revisited.

1. **Conflict copy name:** localized per device. The merging device writes the word in its own
   UI language (`Konflikt` in German, `conflict` in English), because the name is only a label for
   people and the protocol never parses it. The ADR's English pattern is the fallback.
2. **Renewed self-signed certificate:** follows [ADR 6 "Pin rotation"]. On a pin mismatch the
   device ends the connection before it sends anything, keeps working locally and shows "Dein
   Server weist sich anders aus als sonst" (8.3). It takes a new pin from exactly two sources:
   the code or link of one of its own devices that already trusts the new key (it then takes
   only the server address and the pin and does not pair), or a confirmed comparison of the
   server number with the output of the server CLI, with the confirm button held back for 1 s.
   There is no button to accept the new key, and the server number is shown as a row of numbers. A
   server with a public certificate, for example from Let's Encrypt, needs none of this.
3. **Operator restored an older server backup:** follows [ADR 4 "Re-anchor"]. The folder stays
   paused until the person confirms on this device, after comparing the folder number with
   another device, or, without one, explicitly without comparing. Different numbers end the flow
   with "Dann setze nicht fort". The device then merges its local state with the server's state
   by the normal rules, so differing files become two versions, and the versions between the
   restored backup and what the device knew are lost from the history, which the dialog and the
   timeline say. Every affected device confirms for itself (8.6).
4. **Delete a folder on all devices:** one confirmation dialog that names the folder and says how
   long it can be restored. No second confirmation: the retention window is the safety net, and a
   second dialog teaches people to click through.
5. **Re-encrypt after removing a device:** not in version 1, no UI.
6. **Metered networks:** on a metered connection (Windows reports it) uploads and downloads of
   files above 50 MiB wait until the network is unmetered; small files keep syncing. No setting;
   this is not a tray state of its own: the status shows `tray.metered` as its muted second line
   (6.1, 6.3) with a "Sync now" action (`tray.syncNow`) that lets the waiting files go once.

> [!question] Unverified
> That Windows 10 1809 and later report a metered connection to a desktop app (assumed:
> `NetworkInformation.GetInternetConnectionProfile().GetConnectionCost()`). Check before building.
7. **Explorer integration** (navigation pane entry, context menu): after version 1, once measured.


## Changes from the first version (2026-11-26)

Reworked against the current [[0001-foundation]] (sections 3 to 6):

- **8.6, older state:** "No override" and the open box are gone. The folder now continues through
  the re-anchor of ADR 4: compare the folder number with another device and confirm, or confirm
  explicitly without comparing; different numbers end the flow; each device confirms for itself.
  The text says honestly that the local state is merged, that two versions can appear and that
  in-between versions are lost; the timeline marks the spot (9.1).
- **8.3, server identity:** the open box is gone. Two ways back from ADR 6: the code of a device
  that still connects, or comparing the server number with the server CLI, with the confirm
  button held back for 1 s.
- **Decisions 2 and 3** rewritten on the ADR rules, without the old wording.
- **9.4, "Das war ich":** hides the warning on this device only; the shared flag is gone from the
  handover.
- **7.1, conflicts:** grouped by `conflict_of`, never by name; "Diese behalten" gives the chosen
  version the original's name and place, the other stays restorable through the history;
  renaming or moving the copy ends the pairing.
- **9.1, 9.2, restore:** texts for a restore that waits for the daily budget or is refused for
  lack of space or because the version expired.
- **8.4:** headroom used up (deleting does not work either), the upload budget as a muted second
  line instead of "wird synchronisiert" (also 6.1), and quiet notice lines for retained bytes,
  another device's budget and the minimum count cap.
- **13, plural forms:** `Intl.PluralRules` with `.one`, `.other` and, where needed, `.few` and
  `.many`; every key with `{count}` or `{days}` now has both forms in German and English.
- **5, 4.3, 13.2, pairing:** the link and QR path asks only "„{device}“ möchte dazukommen." with
  "Hinzufügen" and "Ablehnen", the numbers are collapsible; only the typed path forces the
  comparison; the confirm button waits 1 s on both.
- **6.5, new:** a chosen folder that is not empty is merged after a question that shows the
  number of local files.
- Example paths use `%USERPROFILE%`.
