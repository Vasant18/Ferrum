# Ferrum KB page brief (shared by all page-builder agents)

You are building ONE OR MORE level pages of a knowledge base for **Ferrum**,
a from-scratch Rust reverse proxy built as a 14-level course in
`/Users/vpujar/MySpace/Reverse_Proxy` (code in `rproxy/src/`). The pages must
teach what WE built — grounded in the actual code and PROGRESS.md — and
compare it honestly to nginx, Apache (httpd), HAProxy, and Envoy.

## Output

One self-contained HTML file per level, saved to
`/Users/vpujar/MySpace/Reverse_Proxy/docs/kb/` with EXACTLY these names:

- Level-01-Core-Networking.html      - Level-08-Security-TLS.html
- Level-02-Routing.html              - Level-09-OS-Internals.html
- Level-03-Load-Balancing.html       - Level-10-Observability.html
- Level-04-Health-Checks.html        - Level-11-Caching.html
- Level-05-Proxy-Headers.html        - Level-12-Production-Features.html
- Level-06-Middleware.html           - Level-13-Basic-WAF.html
- Level-07-Performance.html          - Level-14-Scalability.html

## Non-negotiable style (house rules)

1. **Copy the `<head>` VERBATIM** from
   `/Users/vpujar/.claude/skills/html-knowledge-base/references/azure-head-template.html`.
   Do not hand-write CSS. Azure blue theme only.
2. Body skeleton per
   `/Users/vpujar/.claude/skills/html-knowledge-base/references/structure.md`:
   `header.hero` → `div.layout` containing `nav.toc` (sticky, grouped under
   h2 labels: Orientation / Core / Compare / Reference) + `main` with
   `<section id=...>` blocks → footer.
3. Every TOC `href="#x"` must have a matching `<section id="x">` and
   vice-versa.
4. Teach, don't summarize: each concept gets plain-English what-it-is, a
   concrete example from OUR code (cite `file.rs` and the mechanism), and
   the why. Use `.callout.analogy` liberally; `.callout.warn` for gotchas.
5. Mermaid: `<figure><pre class="mermaid">...</pre><figcaption>...</figcaption></figure>`,
   quote labels containing spaces/punctuation: `A["like this (x)"]`.
   2–4 diagrams per page (request flow, state machines, architecture).
6. Escape `<` `>` `&` in ALL prose and code blocks (`&lt;` etc). Rust
   generics like `Arc<RouteTable>` in prose MUST be `Arc&lt;RouteTable&gt;`.
7. Build incrementally: Write head+hero+toc+first sections, then Edit-append
   (anchor on closing `</main>`) — pages are 40–70 KB.
8. First line of the hero eyebrow: `Ferrum KB · Level N of 14 · <topic>`.
   Include a nav line under the hero linking `<a href="index.html">← Course index</a>`
   plus prev/next level pages by filename.

## Required sections per page (TOC groups in parentheses)

- (Orientation) `exec-summary` — what this level built, in 6–10 sentences.
- (Orientation) `big-picture` — where it sits in the proxy pipeline; a
  mermaid diagram of the request path with this level's stage highlighted.
- (Core) 3–6 concept sections — the level's technical meat: mechanisms,
  design patterns (name them: RAII, sharded locking, type-state, etc.),
  algorithms (name + complexity), the key design decisions AND the
  alternatives rejected (both are in the spec + PROGRESS sections).
- (Core) `code-map` — table of the files/functions this level added or
  changed, with one-line responsibilities (verify against `rproxy/src/`).
- (Compare) `industry` — how nginx, Apache httpd, HAProxy, and Envoy solve
  this level's problem: their mechanism, ours, and the trade-off each
  chose. A `.grid2`/table works. Be honest that ours is a teaching build.
- (Reference) `quiz` — the level's quiz questions COPIED VERBATIM from
  PROGRESS.md (they exist for every level; find them under
  `### Level N quiz`), rendered as an ordered list inside `.qa` blocks or
  `<details>` (no answers — Vessey answers them).
- (Reference) `cheatsheet` — the level's numbers, flags, constants,
  defaults as a compact table; plus a small glossary.

## Sources of truth (read these; do not invent)

- `/Users/vpujar/MySpace/Reverse_Proxy/PROGRESS.md` — per-level "what was
  built" sections and the quizzes (grep `## Level N` / `### Level N quiz`).
- `/Users/vpujar/MySpace/Reverse_Proxy/docs/superpowers/specs/` — design
  docs for levels 3–8 and 10–13 (dated files; read yours).
- `/Users/vpujar/MySpace/Reverse_Proxy/docs/level-9-os-internals.md` and
  `docs/level-14-scalability.md` — theory-level write-ups.
- `rproxy/src/*.rs` — verify any code claim you make (file, function,
  constant values like buffer sizes, defaults). Cite real line-level facts
  sparingly but correctly (e.g. "16 KB windows in `proxy.rs`").
- Industry comparisons: use your own knowledge of nginx/httpd/HAProxy/Envoy
  architecture (event loop models, config models, feature approaches). No
  web fetches needed; qualify anything uncertain with "as of".

## Tone

The course's voice: engineering-first, honest about trade-offs, "explain
the why". The reader is Vessey — a learner who built this alongside Claude
and will use these pages to revise. Do NOT oversell: where ours is crude
vs production (single hash ring vs Maglev, ~16 WAF rules vs CRS thousands,
RwLock vs true arc-swap), say so plainly — those contrasts are the lesson.

## Done means

- File(s) written to docs/kb/ with the exact names above.
- Balanced tags (`section`, `article`, `figure`, `details`, one `main`).
- Every TOC anchor resolves.
- Report back: file name(s), byte size, section count, any claim you could
  not verify in code (list explicitly rather than fudging).
