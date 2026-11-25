---
title: LLM Wiki pattern (Karpathy)
type: source
tags: [wiki, knowledge-base, method]
sources: []
raw: raw/2026-11-25-llm-wiki-pattern.md
url: https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f
retrieved: 2026-11-25
created: 2026-11-25
updated: 2026-11-26
---

# LLM Wiki pattern

Idea file by Andrej Karpathy (gist revision `ac46de1a`) describing a knowledge base that an LLM
agent builds and keeps current, instead of re-deriving answers from raw documents on every query.

> [!note] Local copy only
> The gist carries no license, so its verbatim copy under `raw/` is kept out of the public
> repository. Read the original at the URL above.

## Key points
- Three layers: immutable **raw sources**, the LLM-owned **wiki** of interlinked Markdown pages,
  and the **schema** (here `docs/wiki/CLAUDE.md`) that tells the agent the structure and workflows.
- Three operations: **ingest** (read a source, summarize, update every affected page, index and
  log), **query** (read the index first, answer with citations, file good answers back as pages),
  **lint** (contradictions, stale claims, orphans, missing pages and cross-references, data gaps).
- `index.md` is the content catalog read first on every query; `log.md` is an append-only
  chronicle with a greppable prefix `## [YYYY-MM-DD] <op> | <title>`.
- At moderate scale (about 100 sources, hundreds of pages) the index is enough; a local search
  tool such as qmd becomes useful later.
- Optional tooling: Obsidian (graph view, Web Clipper, Dataview over frontmatter, Marp), images
  downloaded to `raw/assets/`.
- The document is intentionally abstract; the concrete structure is left to the project.

## Significance for Hangar Drive
- The wiki under `docs/wiki/` instantiates this pattern with the same layout as the Hangar wiki,
  minus the agent-CLI category and with file-system and sync topics in its place.
- Frontmatter (`type`, `sources`, dates) keeps the pages queryable with Dataview.
- No search tool yet; the index is enough at the current size.
