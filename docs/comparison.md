# How Secret Guard compares

> **Different threat models, complementary tools.** LiteLLM Guardrails / LLM Guard / PasteGuard
> *detect* unknown PII and secrets in text (pattern recognition, best-effort).
> Secret Guard performs *provable, exact replacement and restoration* of the
> **secrets you declare** — format-indistinguishable realistic mocks, stable across
> turns (prefix-cache friendly), full coverage of streaming and tool calls.
> The two layers compose: a detector as the smoke alarm, a registry as the vault.

**Methodology.** All competitor facts below were verified at source level against these
snapshots: LiteLLM `e5da5933` · LLM Guard `168c1034` · PasteGuard `114c11b7` (Sept 2026).
"not handled" means *not found by inspection*, not a guarantee of absence. We state
competitors' strengths — including where they beat us — as plainly as our own.

## High-level comparison

| | **Secret Guard** | PasteGuard | LLM Guard | LiteLLM |
|---|---|---|---|---|
| **Secret protection** | | | | |
| Exact replacement of declared secrets | ✅ core mechanism | ✅ denylist | ✅ hidden_names | ⚠️ open-source: ad-hoc regex |
| Unknown-value detection (NER / regex / entropy) | 🚧 [roadmap](#our-known-limits) | ✅ GLiNER + regex | ✅ Presidio + NER | ✅ Presidio |
| Placeholder form | **realistic Mock** (equal length, same charset — format-indistinguishable) | typed marker `[[PERSON_1]]` | typed marker (faker optional) | typed marker `<PERSON_1>` |
| Stable across turns (prefix-cache friendly) | ✅ contract-level | ⚠️ within one request | ⚠️ via Vault reuse | ❌ per-request |
| Response restore (incl. tool-call args) | ✅ exact inverse | ✅ exact inverse | ✅ exact + fuzzy tolerance | ✅ exact inverse |
| Streaming restore | ✅ per-chunk | ✅ per-chunk | ❌ | ⚠️ mixed (per-block / buffered) |
| **Gateway** | | | | |
| Cross-protocol translation | ✅ OpenAI ⇄ Anthropic ⇄ Responses (O⇄A incl. streaming) | ❌ same-protocol only | ❌ (library, not a proxy) | ✅ 100+ LLM providers (**their core strength**) |
| Multi-provider routing | ✅ model wildcards + plan pools | — | — | ✅ (**their core strength**) |
| Deployment form | local transparent proxy (change `base_url`) | local proxy + browser extension | embeddable library / REST sidecar | server gateway + SDK |
| **Observability** | | | | |
| Session view (LLM's-eye audit) | ✅ clustered session timeline + Mock highlighting + per-turn delta | ⚠️ request log list | ❌ | ⚠️ request log (post-mask) |
| Usage & cost stats | ✅ tokens / cost / cache-hit (SQLite) | ❌ | ❌ | ✅ spend / budget (**their core strength**) |
| **Engineering** | | | | |
| Runtime | Rust single static binary, no runtime to install | TS (Bun) + Python detector sidecar | Python | Python (+ Rust core parts) |
| License / status | MIT / active | Apache-2.0 / active | MIT / inactive (last push 2026-07) | MIT core + paid enterprise features / active |

## Deep dive: secret protection details

Seven dimensions where the differences actually bite, all source-verified:

### 1. What gets scanned in requests

| | Secret Guard | PasteGuard | LLM Guard | LiteLLM |
|---|---|---|---|---|
| user / tool message text | ✅ | ✅ | caller-supplied | ✅ (messages only) |
| **assistant history** | ✅ (mock-replay probing depends on it) | ❌ excluded by default (`scan_roles`) | caller-supplied | ✅ rescanned |
| **tool-call arguments (request side)** | ✅ all IR blocks | ⚠️ known-value re-mask only | caller-supplied | ❌ |
| **tool results (recursively nested)** | ✅ | ✅ anthropic path | caller-supplied | ❌ |
| system prompt | ✅ | ✅ | caller-supplied | ❌ |
| tools definitions | not scanned (not a secret carrier by design) | ❌ | — | ❌ |
| Responses API / non-chat bodies | ✅ `input[]` fully modeled | ✅ recursive walk | — | ❌ non-chat skipped |

LLM Guard is an embeddable library — "caller-supplied" means it scans whatever text the
host app passes in; per-role coverage is the integrator's decision, not LLM Guard's.

### 2. In-context collision protection

If a replacement value coincides with existing request text, restore wrongly replaces it.

| | mechanism |
|---|---|
| Secret Guard | ✅ **probing candidate chain** — each mock is probed against the whole request context, collision ⇒ next candidate (contract RED-2) + map-insert collision check |
| PasteGuard | ❌ no content probing |
| LLM Guard | ⚠️ index-allocation avoidance only, no content probing |
| LiteLLM | ❌ no probing; per-message placeholder numbering restarts at 1 while sharing one map dict across messages → placeholder keys overwrite each other (`presidio.py` lines 715–741 at snapshot `e5da5933`) |

### 3. Information content of the replacement

| | form | real-value substring leak? | per-secret configurability |
|---|---|---|---|
| Secret Guard | realistic Mock (equal length, same charset) | none — mathematically excluded: no ≥k(L)-char contiguous substring of the real value, k(L) adaptive (contract C5/RED-5) | ✅ initial value / charset / length range / global prefix + config-time lint |
| PasteGuard | typed marker | none (pure label) | ❌ hardcoded format |
| LLM Guard | typed marker or faker value | possible: faker values unchecked against real | ❌ hardcoded templates |
| LiteLLM | typed marker | none (pure label) | ❌ hardcoded templates |

### 4. Degradation semantics (where do secrets go when parsing fails)

| | behavior |
|---|---|
| Secret Guard | **fail-safe by default** (SEC-10): response-parse failure ⇒ keep the Mock (real value never lands in a failure body); probe exhaustion / unsupported protocol ⇒ reject the request (503). Three switches, all defaulting to the safe side. |
| PasteGuard | error responses (leaks neither) |
| LLM Guard | n/a (library) |
| LiteLLM | mixed: streaming-mask failure path can forward unmasked chunks; SSE parse failure passes lines through unrestored (placeholder leaks to the client). |

### 5. Historical mocks replayed by the client

Clients echo assistant history (with mocks) back in later turns:

| | behavior |
|---|---|
| Secret Guard | ✅ guaranteed by contract: old mocks are recognized, the probing counter advances, and **restore correctness takes priority over cache stability** (RED-3 adjudication; round-trip guaranteed) |
| PasteGuard | ⚠️ old placeholders not exempted / not restored (depends on detector re-hitting them) |
| LLM Guard | ⚠️ Vault replaces all historical placeholders, however old |
| LiteLLM | ⚠️ per-request rescan + numbering restart; on collision restores to the wrong real value (consequence of #2) |

### 6. Multiple / overlapping secrets

| | same value multiple spots | overlapping (long secret contains short) |
|---|---|---|
| Secret Guard | ✅ one mapping | ✅ **longest-first** (dedicated test) |
| PasteGuard | ✅ reuse within request | ⚠️ first-come-first-served on the secrets line (early start wins, longer spans dropped; code comment says longest-match-wins, implementation is first-match); PII line: greedy by score |
| LLM Guard | ✅ Vault reuse | ✅ conflict pruning by score |
| LiteLLM | ❌ one token per span | ⚠️ longest within same type; no cross-type nesting protection (reverse-order replacement corrupts both, orphaned mappings remain) |

### 7. Registry vs detection

| | declared-value registry | unknown-value detection | secret management |
|---|---|---|---|
| Secret Guard | ✅ core (`value`/`value_file`, WebUI CRUD, per-secret enable) | 🚧 roadmap | two-layer config + WebUI + per-entry enable/override (persisted) |
| PasteGuard | ✅ denylist | ✅ | yaml |
| LLM Guard | ✅ hidden_names | ✅ | code-constructed |
| LiteLLM | ⚠️ open-source: ad-hoc regex | ✅ | yaml |

## Where alternatives are stronger

Honest score, so you can pick the right tool:

- **LiteLLM**: 100+ LLM providers (vs our 3 codec families), virtual keys / budgets / spend
  limits, 40+ guardrail integrations, team multi-tenancy. If you run an org-wide gateway,
  that is a different weight class.
- **PasteGuard / LLM Guard / LiteLLM** all detect **unknown** PII/keys you never declared
  (NER / regex / entropy). We deliberately don't guess — zero false positives and an exact
  bijection instead — but if you don't know what you're leaking, a detector is the right
  first layer (and pairs well with us).
- **PasteGuard** also ships a browser extension covering ChatGPT/Claude/Gemini web chats —
  a scenario outside our API-gateway scope.

## Our known limits

- No unknown-value detection (registry-only) — detector-style (NER/regex/entropy) detection
  as an alerting layer is on the [roadmap](../README.md#roadmap--contributing).
- Codec covers OpenAI / Anthropic / Responses; Gemini / Ollama are forwarded as
  transparent byte pass-through without Redact (rejected by default when secrets are
  configured). Streaming on the Responses side returns 501 whenever Redact is involved —
  same- or cross-protocol — rather than risking silent Mock leaks.
- Binaries published for Linux only (macOS/Windows: build from source / WSL).
