"""Tests for tools/third_party_notices.py and the release files it feeds.

Run: py -3 -m unittest discover tools
"""

import json
import re
import shutil
import unittest
from pathlib import Path

import third_party_notices as notices

ROOT = Path(__file__).resolve().parent.parent
TMP = ROOT / "tests" / ".tmp" / "notices"


def crate(name: str, license: str, text: str | None) -> notices.Crate:
    directory = TMP / name
    directory.mkdir(parents=True, exist_ok=True)
    if text is not None:
        (directory / "LICENSE").write_text(text, encoding="utf-8")
    return notices.Crate(name, "1.0.0", license, f"https://example.org/{name}", directory)


class RenderTest(unittest.TestCase):
    def setUp(self) -> None:
        shutil.rmtree(TMP, ignore_errors=True)

    def tearDown(self) -> None:
        shutil.rmtree(TMP, ignore_errors=True)

    def test_lists_only_crates_without_an_allowed_alternative(self) -> None:
        out = notices.render(
            [
                crate("plain", "MIT OR Apache-2.0", "MIT text"),
                crate("either", "CC0-1.0 OR MIT-0 OR Apache-2.0", "CC0 text"),
                crate("mpl", "MPL-2.0", "MPL text"),
                crate("boost", "BSL-1.0", "Boost text"),
            ]
        )
        self.assertIn("| mpl | 1.0.0 | MPL-2.0 | <https://crates.io/crates/mpl/1.0.0> |", out)
        self.assertIn("| boost | 1.0.0 | BSL-1.0 |", out)
        self.assertNotIn("| plain |", out)
        self.assertNotIn("| either |", out)
        self.assertIn("MPL text", out)
        self.assertIn("Boost text", out)

    def test_a_crate_without_a_license_file_takes_the_text_of_the_same_license(self) -> None:
        out = notices.render([crate("a", "MPL-2.0", "MPL text"), crate("b", "MPL-2.0", None)])
        self.assertIn("the text is the one of a 1.0.0, under the same license", out)
        # One text, used by both.
        self.assertEqual(out.count("MPL text"), 1)
        self.assertIn("Used by: a 1.0.0, b 1.0.0.", out)

    def test_a_crate_without_any_text_fails_loudly(self) -> None:
        with self.assertRaises(SystemExit):
            notices.render([crate("lonely", "BSL-1.0", None)])


class ReleaseFilesTest(unittest.TestCase):
    def test_the_notices_follow_cargo_lock(self) -> None:
        if shutil.which("cargo") is None:
            self.skipTest("cargo is not on PATH")
        self.assertEqual(notices.main(["--check"]), 0, "run py -3 tools/third_party_notices.py")

    def test_the_notices_name_the_exceptions_of_adr_0001_section_8(self) -> None:
        text = (ROOT / "THIRD_PARTY_NOTICES.md").read_text(encoding="utf-8")
        for name in ("option-ext", "cssparser", "selectors", "dtoa-short", "xxhash-rust", "clipboard-win"):
            self.assertRegex(text, rf"\n\| {re.escape(name)} \| [0-9.]+ \| (MPL|BSL)", name)
        self.assertIn("Mozilla Public License Version 2.0", text)
        self.assertIn("Boost Software License - Version 1.0", text)

    def test_the_bundle_ships_the_notices(self) -> None:
        conf = json.loads((ROOT / "src-tauri" / "tauri.conf.json").read_text(encoding="utf-8"))
        self.assertEqual(
            conf["bundle"]["resources"], {"../THIRD_PARTY_NOTICES.md": "THIRD_PARTY_NOTICES.md"}
        )

    # Security review, information finding: the reverse proxy example names its image by digest.
    def test_the_caddy_example_is_pinned_by_digest(self) -> None:
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        images = re.findall(r"image:\s*(caddy\S*)", compose)
        self.assertEqual(len(images), 1, images)
        self.assertRegex(images[0], r"^caddy:[0-9][^@]*@sha256:[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
