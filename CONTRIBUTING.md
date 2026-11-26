# Contributing to Hangar Drive

Thanks for your interest. Bug reports, ideas and pull requests are welcome.
Everyone taking part follows the [Code of Conduct](CODE_OF_CONDUCT.md).

## Before you start

- For larger changes, open an issue first so we can agree on the approach.
- The rules below apply to every change; design decisions are recorded in [`docs/wiki`](docs/wiki/index.md).
  Please write issues and pull requests in English.

## Development

Hangar Drive is a Tauri 2 app (Rust backend, React and TypeScript frontend, pnpm) with a sync server
in Rust. It needs Rust, Node.js, pnpm and the
[Tauri prerequisites](https://v2.tauri.app/start/prerequisites/); Docker only for the server image.
All Rust packages (`src-tauri`, `crates/hangar-drive-protocol`, `crates/hangar-drive-crypto`,
`server`) form one Cargo workspace at the repository root.

```sh
pnpm install
pnpm tauri dev
```

The whole check suite must pass before a pull request is merged:

```sh
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
pnpm format:check && pnpm lint && pnpm test && pnpm build
py -3 crates/hangar-drive-crypto/test_vectors.py
py -3 -m unittest discover tools
py -3 tools/third_party_notices.py --check
```

The Cargo commands run from the repository root and cover every Rust package of the workspace.
`pnpm build` comes before the first Cargo build, because the app embeds the built frontend.
`test_vectors.py` recomputes the crypto crate's fixed test vectors (`testdata/vectors.json`) with the
Python standard library, independently of the Rust code. It needs Python 3.14, whose `unicodedata`
has the Unicode version of the name policy; on Linux and macOS run it as `python3`.
After a deliberate format change, regenerate the file with `--write` and review the diff.
The two lines after it test the Python tools and check that `THIRD_PARTY_NOTICES.md` still follows
`Cargo.lock`; after a dependency change, regenerate it with `py -3 tools/third_party_notices.py`.
A change to the server should also pass an image build:
`docker build -f server/Dockerfile -t hangar-drive-server .`

`pnpm tauri build` builds an installer.

## Guidelines

- **Commits:** [Conventional Commits](https://www.conventionalcommits.org) in English
  (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`), one logical change per commit.
- **Tests:** new behavior comes with a test. A bug gets a failing test first, then the fix. Tests are
  never weakened to make them pass. Test files go under the git-ignored `tests/.tmp/`, never into the
  system temp folder.
- **Rust:** no `unwrap`/`expect` outside tests unless an invariant is documented; `thiserror` in
  modules; `unsafe` only with a `// SAFETY:` comment.
- **TypeScript:** `strict`, no `any`, no unchecked casts.
- **Processes:** always start programs as an argv array, never as a shell string.
- **Shortcuts:** never bind `Ctrl+<letter>` alone where a text field needs it. Shortcuts live in one
  module and have tests.
- **Dependencies:** add one only with a justification covering maintenance status, license
  (MIT, Apache-2.0 or BSD) and size.
- **UI text:** add every new string to the i18n module in all supported languages.

## License

By contributing you agree that your contribution is licensed under the [MIT License](LICENSE).
