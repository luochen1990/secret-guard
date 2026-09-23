<p align="center">
  <img src="assets/logo.svg" width="110" alt="Secret Guard logo">
</p>

# Secret Guard

**A lightweight local LLM gateway: outbound requests have their Secrets replaced with
equal-length realistic Mocks; responses are restored back to real values on the way in —
the LLM never touches a real Secret, while your Agent tools keep working.**

[Docs](https://secret-guard.lambda.lc/en/) · [Download](https://secret-guard.lambda.lc/en/download/) · [Quick Start](https://secret-guard.lambda.lc/en/tutorial-quick-start/) · [Protocol Support](#protocol-support) · [简体中文](./README.zh-CN.md)

## Why Secret Guard?

Agent tools (claude-code / opencode / hermes-agent and friends) do your work by stuffing
material wholesale into the prompt — code, configuration, terminal output, along with the
passwords, private keys, tokens, and cookies in them, all delivered to the LLM Provider's
servers. Once that data leaves your machine, it is out of your control: it may end up in
Provider logs, be used for model training, or leak in a breach.

And "never put Secrets in the context" is simply not viable in Agent workflows —
credentials are exactly what an Agent needs to act on real systems on your behalf.
Secret Guard resolves this tension: **your Agent keeps working with your Secrets, while
the LLM never touches a real value.**

## How it works

The only integration cost is one line: point your Agent tool's API base URL at the local
gateway, and traffic flows through it to the Provider:

```text
Outbound:  Agent tool ──real Secret──►  secret-guard  ──realistic Mock──►  LLM Provider
Return:    local tools ◄──real Secret──  secret-guard  ◄──Mock reply────  LLM Provider
                        (Redact / Restore both happen locally, transparent in both directions)
```

- **Outbound Redact**: Secrets in requests bound for the LLM are replaced with
  equal-length, same-charset realistic Mocks (default strategy) — the LLM keeps working
  with them, none the wiser.
- **Return Restore**: when LLM responses come back (tool-call arguments included), Mocks
  are restored to real values — a curl command carrying a Secret lands on your machine
  with authentication passing as usual.

The same request, before and after it leaves the machine (captured from a real run; only
the token value is fictional):

```text
Agent sends:       GITHUB_TOKEN=ghp_0123456789abcdefghijklmnopqrstuvwxyz
Provider receives: GITHUB_TOKEN=2_9rr_61dr1lmv2wf15aotyyt262l3t9_2pt4uih
```

A quick tour of the WebUI — session timeline, the LLM's-eye request view with the Mock
highlighted, and the restored real value on the response side:

![WebUI demo](assets/demo.gif)

Every forward can be inspected in the WebUI's Records page (session timeline + request
detail, with Secret locations highlighted as the Mock — i.e. exactly what the LLM saw):

![WebUI Records page — session timeline and request detail (LLM's view)](assets/records-detail.webp)

## Quick Start

### 1. Install

```bash
# Binary archives (Linux x86_64 / ARM64, fully static musl, with SHA256 checksums):
#   https://github.com/luochen1990/secret-guard/releases
#   archive name pattern: secret-guard-<version>-<triple>.tar.gz
#   (e.g. secret-guard-0.1.0-x86_64-linux-musl.tar.gz)

# Nix (flake):
nix run github:luochen1990/secret-guard -- --help
# or wire up the overlay / nixosModule into your flake and use pkgs.secret-guard

# Cargo (builds from source, requires rustc >= 1.96):
cargo install --git https://github.com/luochen1990/secret-guard
# or after cloning the repository: cargo install --path .
```

> NixOS users should prefer the `services.secret-guard.*` structured-options deployment
> (config validated at eval time, credentials injected via files) — see
> [docs/deployment-nixos.md](docs/deployment-nixos.md).

### 2. Minimal configuration

Create `secret-guard.toml` somewhere (one upstream provider + one secret to protect is
all it takes):

```toml
[[providers]]
id = "openai-main"
kind = "direct"                         # direct upstream (use "router" for routing endpoints, "pool" for plan pools)
api_key = "sk-your-upstream-key"        # entry-level credential shared by all endpoints — must come BEFORE [[providers.endpoints]] (TOML sub-table switch)
[[providers.endpoints]]
protocol = "openai"                     # at most one [[providers.endpoints]] per protocol;
base_url = "https://api.openai.com"     # unmatched ingress protocols fall back to the first endpoint

[[secrets.entries]]
id = "my-github-token"
value = "ghp_0123456789abcdefghijklmnopqrstuvwxyz"   # the secret to protect (never sent upstream)
```

> Mind the nesting: secrets live under `[[secrets.entries]]` while providers are flat
> `[[providers]]` (the two styles differ). Full field reference:
> [docs/configuration.md](docs/configuration.md).

### 3. Start and send the first request

```bash
secret-guard run --port 18787
curl http://127.0.0.1:18787/o/openai-main/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"My token is ghp_0123456789abcdefghijklmnopqrstuvwxyz, please summarize."}]}'
```

The upstream receives a realistic Mock — `redactions=1` in the forward-completion log is
the replacement count; open `http://127.0.0.1:18787/` in a browser to review the request
in the Records page.

> Examples use port `18787` throughout; the default listen address is `127.0.0.1:8787`
> (changeable via `[server] port` or the `SG_PORT` environment variable).

For daily use, just point your Agent tool's `base_url` at the gateway — no curl needed:

```python
from openai import OpenAI
client = OpenAI(base_url="http://127.0.0.1:18787/o/openai-main/v1", api_key="ignored")
```

### Routing convention

URLs take the form `/{proto_short}/{provider_id}/*rest`, encoding both the **ingress
protocol** and the **target provider**:

| proto_short | Protocol | SDK example (`base_url`) |
|---|---|---|
| `o` | OpenAI | `http://127.0.0.1:18787/o/<provider-id>/v1` |
| `a` | Anthropic | `http://127.0.0.1:18787/a/<provider-id>` |
| `g` | Gemini | `http://127.0.0.1:18787/g/<provider-id>` |
| `l` | Ollama | `http://127.0.0.1:18787/l/<provider-id>` |
| `r` | Responses (OpenAI Responses API) | `http://127.0.0.1:18787/r/<provider-id>/v1` |

> SDK notes: the OpenAI SDK needs the `/v1` prefix included yourself; the Anthropic SDK
> appends `/v1/messages` on its own, so `http://.../a/<provider-id>` is enough.

### Two-layer configuration

- `secret-guard.toml` — declarative config, hand-written, read-only in the process.
- `secret-guard.state.toml` — dynamic state the WebUI persists on edit; delete it to
  reset. A dynamic source can override the static one for the same entity.

> ⚠️ **Sensitive data warning**: `state.toml` contains **plaintext** secrets (WebUI-created
> secret values, explicitly written provider api_keys) at the same sensitivity level as
> `secret-guard.toml` — keep it in `.gitignore`; an accidental commit leaks Secrets into
> version history.

### Logs and troubleshooting

Every completed forward logs a one-line INFO summary
(`forward ... status=... elapsed_ms=... redactions=N provider=...`), so you can confirm
traffic passes through secret-guard from the command line; upstream failures (502/504)
carry readable causes in the error body. Lower the verbosity with
`RUST_LOG=secret_guard=warn` (default `info`) when it gets noisy.

## Why you can trust it

Handing production traffic to an intermediary process requires proof it won't get in the
way. The following properties are pinned in the repository by property-based tests and
end-to-end integration tests, fully verified on every release:

- **Transparent relay**: without Redact, byte-exact pass-through; with Redact, nothing
  changes semantically except the real↔mock swap (only serialization noise like field
  order) — behavior is indistinguishable from a direct connection.
- **Strictly reversible**: every Mock maps one-to-one to a real value, and Restore is the
  exact inverse of Redact — tool calls carrying Secrets are never corrupted.
- **Deterministic Mocks**: a Secret's Mock is stable across turns, preserving Provider
  prefix-cache hits — token cost is unaffected in normal sessions (the
  mock-escaped-and-replayed exception is documented).
- **No collisions in context**: a Mock never coincides with other content in the request,
  so responses are never wrongly replaced.
- **Multi-provider routing**: multiple providers (OpenAI / Anthropic / Gemini / Ollama /
  Responses) with per-request model-wildcard routing to different upstreams.
- **Plan-pool failover (Pool)**: chain multiple coding-plan subscriptions (each with its
  own credential) behind one endpoint; when one plan hits its usage-window limit, traffic
  fails over to the next one automatically and switches back once the window resets —
  zero manual intervention.
- **On-demand verbose logging**: by default the gateway stays memory-lean (the session
  timeline keeps working); flip one toggle in the WebUI and subsequent requests capture
  full request/response bodies for troubleshooting.

A source-level comparison with LiteLLM / LLM Guard / PasteGuard — seven
secret-protection dimensions, including where the alternatives are stronger:
[docs/comparison.md](docs/comparison.md).

## Protocol Support

| Protocol | Forwarding | Secret Redact | Cross-protocol translation |
|---|---|---|---|
| OpenAI (Chat Completions) | ✅ | ✅ | ✅ ⇄ Anthropic (incl. streaming) / ⇄ Responses (incl. streaming) |
| Anthropic (claude) | ✅ | ✅ | ✅ ⇄ OpenAI (incl. streaming) / ⇄ Responses (incl. streaming) |
| OpenAI Responses | ✅ | ✅ (incl. streaming) | ✅ ⇄ Chat Completions / Anthropic (incl. streaming) |
| Gemini / Ollama | ✅ byte pass-through | 🚧 [Roadmap](#roadmap--contributing) | 🚧 [Roadmap](#roadmap--contributing) |

- Gemini / Ollama are transparent byte pass-through (forwarding itself fully works);
  the codec does not cover them yet, so Redact does not apply — with secrets configured,
  requests on those protocols are **rejected by default** (503,
  `[redact] on_unsupported_protocol = "fail_closed"`; the error message carries a hint).
  They can still be created via hand-written config / the REST API (fine for secret-free
  pure forwarding); the WebUI creation form does not offer them, but editing an existing
  entry or a Detect probe recommendation supports them via "(experimental)" options.
- **Fail-safe degradation**: on Redact's abnormal paths (unparsable upstream responses /
  non-2xx), Mocks are passed through by default — real values never land in failure
  bodies; `on_fallback_restore = "restore"` opts into restoration. Full semantics of the
  three degradation switches: [docs/configuration.md](docs/configuration.md).
- Protocol behavior is pinned by property-based tests and simulated-upstream integration
  tests; real-Provider field validation for Anthropic / Gemini / Ollama has not happened
  yet (see [Roadmap](#roadmap--contributing)) — when first adopting those protocols,
  verify one real request in the WebUI Records page before going full speed.

## Roadmap & Contributing

The following directions are in progress — issues and PRs welcome at the main repository
[github.com/luochen1990/secret-guard](https://github.com/luochen1990/secret-guard);
the full development guide lives in [AGENTS.md](AGENTS.md):

- **Gemini / Ollama codec**: bring Redact and cross-protocol support to these families.
  A new protocol only needs a Reader + Writer trait implementation (~200 lines) with no
  dispatch changes — see `src/codec/AGENTS.md` for the architecture.
- **Responses streaming fidelity**: close the residual known losses of Responses
  streaming translation (hosted tools / refusal parts dropped with WARN, reasoning
  delta event-type normalization, multi content part folding) — streaming itself,
  including the Redact restore path, now works for every codec-covered pair; tracked
  in [docs/known-limitations.md](docs/known-limitations.md).
- **Unknown-secret detection (NER / regex / entropy) as an alerting layer**: flag
  suspected undeclared secrets in the WebUI without auto-redacting (zero false-positive
  replacements stay guaranteed). See [#252](https://git.lambda.lc/lc-studio/secret-guard/issues/252).
- **Real-Provider field validation**: integration-test profiles against real upstreams
  for the protocol matrix.

## Docs

You might be looking for:

- Your first Redact-protected request in three minutes → [Quick Start (site)](https://secret-guard.lambda.lc/en/tutorial-quick-start/)
- Full configuration field reference → [docs/configuration.md](docs/configuration.md)
- WebUI page-by-page guide → [WebUI Guide (site)](https://secret-guard.lambda.lc/en/manual-webui/)
- NixOS deployment and credential injection → [docs/deployment-nixos.md](docs/deployment-nixos.md)
- Architecture and dataflow contracts → [docs/design/](docs/design/) (contracts.md)
- Source-level comparison with alternatives → [docs/comparison.md](docs/comparison.md)
- Development workflow / test strategy / module contracts → [AGENTS.md](AGENTS.md)

## License

MIT — see [LICENSE](LICENSE).
