# Wikipedia (German): "Versionsnummer"

- URL: https://de.wikipedia.org/wiki/Versionsnummer
- Retrieved: 2026-11-26 (page state: last edited 2026-06-09)
- License of the article: CC BY-SA 4.0. This file is an own English summary of the relevant
  sections, not a copy or translation of the article text.

## Sections of the article

Lead, "Semantische Versionsnummer", "Versionsnummer mit Datum", "Marketingaspekte",
"Ergänzungen", "Einzelnachweise".

## Summary of the relevant sections

### Lead
Version numbers tell versions of a software product apart and make its progress traceable. They
are the basis of version control; assigning them is called versioning.

### Semantic version number
- A common structure has three main parts and a build number, written for example as
  `2.3.5-0041`: major version, minor version, revision, build number.
- Major version: usually a very significant change, such as a rewrite or a break of interface
  compatibility of a library.
- Minor version: usually new functionality.
- Revision (also patch level or micro): usually bug fixes.
- Build number: counts single build steps and usually grows with every build. With version
  control, an identifier that pins the source state in the version control system is often used
  instead, which makes it easy to find the matching sources.
- Each part can have several digits: 0.9 is followed by 0.10, not by 1.0. Leading zeros (0.09) are
  sometimes used when many versions are expected.
- When the major or minor version goes up, the parts after it are reset to 0, except the build
  number. Example: from 2.3.5 to 2.3.6, 2.4.0 or 3.0.0, depending on the size of the change.
- Major version 0 is often treated as an exception: raising the minor version may then also stand
  for large changes.
- There is no binding standard for the meaning of the parts, only conventions. .NET, for
  example, uses the order major.minor.build.revision and distinguishes a file version, an
  informational (product) version and an assembly version.
- Many open source projects stay below 1.0 for a long time, even when they are mature.
- A prefix "v" or "V" is common in notation.
- The references name the Semantic Versioning 2.0.0 specification.

### Version number with a date
A date-based scheme uses year.month.day plus a build number within the day, for example
`2024.10.12-0002`.

### Additions
Labels for the stages before and at a release: alpha (very early), beta (tested by a limited
group), release candidate (last test version), release (final). A patch (patch level, "pl") is a
correction level.

## Not covered by the article
- Rules for comparing or sorting versions beyond the 0.9 / 0.10 example and the reset rule.
- The SemVer rules for pre-release and build metadata (only linked through the references).
