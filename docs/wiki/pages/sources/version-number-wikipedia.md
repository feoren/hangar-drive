---
title: "Wikipedia: version number"
type: source
tags: [version, release]
sources: []
raw: raw/2026-11-26-version-number-wikipedia.md
url: https://de.wikipedia.org/wiki/Versionsnummer
retrieved: 2026-11-26
created: 2026-11-26
updated: 2026-11-26
---

# Wikipedia: version number

Own summary of the German Wikipedia article "Versionsnummer" (CC BY-SA 4.0, page state of
2026-06-09). The raw file holds a longer summary, not the article text.

## Key points
- Common scheme: **major version** (fundamental or incompatible change), **minor version** (new
  functionality), **revision** (patch level, bug fixes) and a **build number** that counts single
  build steps, written for example as `2.3.5-0041`.
- With version control, an identifier that pins the source state is often used as the build number,
  so the sources of a build are easy to find.
- Raising the major or minor version resets the parts after it to 0, except the build number.
- Each part can have several digits: 0.9 is followed by 0.10, not 1.0. Major version 0 is often an
  exception in which the minor version may also stand for large changes.
- There is no binding standard, only conventions; .NET orders the four parts differently
  (major.minor.build.revision).
- Labels before a release: alpha, beta, release candidate; a date-based scheme
  (`2024.10.12-0002`) exists as an alternative.
- The article does not state comparison rules beyond 0.9 / 0.10 and does not explain the SemVer
  rules for pre-release and build metadata.

## Significance for Hangar Drive
Basis of [[0002-version-scheme]]: the four parts, their meaning, the never reset build number tied to
the Git state and the freedom of the minor version while the major version is 0.
