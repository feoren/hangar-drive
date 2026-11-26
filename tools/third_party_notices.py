"""Writes THIRD_PARTY_NOTICES.md from `cargo metadata`, so the notices follow Cargo.lock.

The desktop app ships every crate its package `hangar-drive` reaches through normal
dependencies (not dev or build dependencies), on every target platform. Of those, the crates
under a license outside the project's allowlist (deny.toml `licenses.allow`) are the exceptions
of ADR 0001, section 8: MPL-2.0 (a file-level copyleft whose recipients must learn where the
source is), BSL-1.0, CC0-1.0 and CDLA-Permissive-2.0. This script lists each of them with its
version, license, source and the full license text, taken from the crate as published on
crates.io. A crate that ships no license file gets the text of another listed crate with the
same SPDX license, and the notice says so.

The output is deterministic (sorted, no dates), so a second run on the same Cargo.lock writes
the same bytes.

Run from the repository root:
    py -3 tools/third_party_notices.py          # writes THIRD_PARTY_NOTICES.md
    py -3 tools/third_party_notices.py --check  # fails when the file is out of date
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "THIRD_PARTY_NOTICES.md"
APP_PACKAGE = "hangar-drive"
# The licenses that need a notice: everything shipped that deny.toml allows only as an exception.
NOTICE_LICENSES = ("MPL-2.0", "BSL-1.0", "CC0-1.0", "CDLA-Permissive-2.0")
LICENSE_FILE_PREFIXES = ("license", "licence", "copying")
# deny.toml `licenses.allow`: a crate that may be used under one of these needs no notice here.
ALLOWED = ("MIT", "Apache-2.0", "BSD-3-Clause", "ISC", "Zlib", "Unicode-3.0")


@dataclass(frozen=True)
class Crate:
    name: str
    version: str
    license: str
    repository: str
    directory: Path

    @property
    def source(self) -> str:
        return f"https://crates.io/crates/{self.name}/{self.version}"

    @property
    def notice_licenses(self) -> tuple[str, ...]:
        """The notice licenses the crate is used under: none when an `OR` alternative of the
        expression is on the allowlist (cargo deny then takes that one)."""
        alternatives = [a.strip(" ()") for a in self.license.split(" OR ")]
        if len(alternatives) > 1 and any(a in ALLOWED for a in alternatives):
            return ()
        return tuple(lic for lic in NOTICE_LICENSES if lic in self.license)


def cargo_metadata() -> dict:
    """The workspace's metadata for every platform, from Cargo.lock as it is."""
    result = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--locked"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return json.loads(result.stdout)


def shipped_crates(metadata: dict) -> list[Crate]:
    """Every package the app reaches through normal dependencies, the app itself excluded."""
    packages = {p["id"]: p for p in metadata["packages"]}
    nodes = {n["id"]: n for n in metadata["resolve"]["nodes"]}
    roots = [p["id"] for p in metadata["packages"] if p["name"] == APP_PACKAGE and p["source"] is None]
    if len(roots) != 1:
        raise SystemExit(f"expected one workspace package {APP_PACKAGE}, found {len(roots)}")
    seen = set(roots)
    stack = list(roots)
    while stack:
        node = nodes[stack.pop()]
        for dep in node["deps"]:
            normal = any(kind["kind"] is None for kind in dep["dep_kinds"])
            if normal and dep["pkg"] not in seen:
                seen.add(dep["pkg"])
                stack.append(dep["pkg"])
    seen.difference_update(roots)
    crates = []
    for package_id in seen:
        p = packages[package_id]
        crates.append(
            Crate(
                name=p["name"],
                version=p["version"],
                license=p.get("license") or "",
                repository=p.get("repository") or "",
                directory=Path(p["manifest_path"]).parent,
            )
        )
    return sorted(crates, key=lambda c: (c.name, c.version))


def license_file(crate: Crate) -> Path | None:
    """The crate's own license file, the first by name."""
    files = sorted(
        f for f in crate.directory.iterdir() if f.is_file() and f.name.lower().startswith(LICENSE_FILE_PREFIXES)
    )
    return files[0] if files else None


def normalized(text: str) -> str:
    return "\n".join(line.rstrip() for line in text.replace("\r\n", "\n").strip().split("\n"))


def render(crates: list[Crate]) -> str:
    noticed = [c for c in crates if c.notice_licenses]
    # The text of each crate: its own file, else the file of a listed crate with the same license.
    texts: dict[str, str] = {}
    origin: dict[str, str] = {}
    for crate in noticed:
        found = license_file(crate)
        if found is not None:
            texts[crate.name + "@" + crate.version] = normalized(found.read_text(encoding="utf-8"))
    for crate in noticed:
        key = crate.name + "@" + crate.version
        if key in texts:
            continue
        donor = next(
            (
                other
                for other in noticed
                if other.notice_licenses == crate.notice_licenses and other.name + "@" + other.version in texts
            ),
            None,
        )
        if donor is None:
            raise SystemExit(f"{key}: no license file and no other crate under {crate.license}")
        texts[key] = texts[donor.name + "@" + donor.version]
        origin[key] = f"{donor.name} {donor.version}"

    # Each distinct text once, numbered in order of first use.
    distinct: list[str] = []
    for crate in noticed:
        text = texts[crate.name + "@" + crate.version]
        if text not in distinct:
            distinct.append(text)

    out = [
        "# Third-party notices",
        "",
        "Hangar Drive is MIT licensed. The desktop app is built from Rust crates published on",
        "crates.io; nearly all of them are under MIT, Apache-2.0, BSD-3-Clause, ISC, Zlib or",
        "Unicode-3.0. The crates below are under other licenses (decision record 0001, section 8)",
        "and are listed here with their full license texts. Every one of them is used unmodified;",
        "its complete source is the published crate at the address given.",
        "",
        "For the crates under the Mozilla Public License 2.0, that address is where the source of",
        "the covered files is available (MPL-2.0, section 3.2). No file of Hangar Drive itself is",
        "covered by the MPL.",
        "",
        "This file is generated by `tools/third_party_notices.py` from `cargo metadata`; do not edit",
        "it by hand.",
        "",
        "| Crate | Version | License | Source |",
        "| ----- | ------- | ------- | ------ |",
    ]
    for crate in noticed:
        out.append(f"| {crate.name} | {crate.version} | {crate.license} | <{crate.source}> |")
    out.append("")
    for crate in noticed:
        key = crate.name + "@" + crate.version
        number = distinct.index(texts[key]) + 1
        out += [
            f"## {crate.name} {crate.version}",
            "",
            f"- License: {crate.license}",
            f"- Source: <{crate.source}>",
        ]
        if crate.repository:
            out.append(f"- Repository: <{crate.repository}>")
        if key in origin:
            out.append(
                f"- The crate ships no license file; the text is the one of {origin[key]}, under the same license."
            )
        out += [f"- License text: [text {number}](#license-text-{number})", ""]
    for number, text in enumerate(distinct, start=1):
        users = ", ".join(
            f"{c.name} {c.version}" for c in noticed if texts[c.name + "@" + c.version] == text
        )
        out += [
            f'<a id="license-text-{number}"></a>',
            "",
            f"## License text {number}",
            "",
            f"Used by: {users}.",
            "",
            "```text",
            text,
            "```",
            "",
        ]
    return "\n".join(out)


def main(argv: list[str]) -> int:
    content = render(shipped_crates(cargo_metadata()))
    if "--check" in argv:
        current = OUTPUT.read_text(encoding="utf-8") if OUTPUT.exists() else ""
        if current != content:
            print(f"{OUTPUT.name} is out of date: run py -3 tools/third_party_notices.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT.write_text(content, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
