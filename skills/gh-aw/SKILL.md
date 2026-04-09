---
name: gh-aw
description: >
  Create and maintain GitHub Agentic Workflows (gh-aw) for Prowler.
  Trigger: When creating agentic workflows, modifying gh-aw frontmatter, configuring safe-outputs,
  setting up MCP servers in workflows, importing Copilot Custom Agents, or debugging gh-aw compilation.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root]
  auto_invoke:
    - "Creating GitHub Agentic Workflows"
    - "Modifying gh-aw workflow frontmatter or safe-outputs"
    - "Configuring MCP servers in agentic workflows"
    - "Importing Copilot Custom Agents into workflows"
    - "Debugging gh-aw compilation errors"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch
---

## When to Use

- Creating new `.github/workflows/*.md` agentic workflows
- Modifying frontmatter (triggers, permissions, safe-outputs, tools, MCP servers)
- Creating or importing `.github/agents/*.md` Copilot Custom Agents
- Debugging `gh aw compile` errors or warnings
- Configuring network access, rate limits, cost budgets, cache, or memory
- Investigating runs with `gh aw audit` / `gh aw logs`

## Source of Truth

**Always read gh-aw docs from the repo source, not the rendered site.** Authors edit markdown in `github/gh-aw`; the rendered site can lag.

```bash
# List every reference page
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference' --jq '.[] | .name'

# Read a specific page (raw)
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference/engines.md' --jq '.content' | base64 -d
```

Top-level doc directories: `reference/`, `guides/`, `introduction/`, `setup/`, `patterns/`.

---

## File Layout

```
.github/
├── workflows/
│   ├── {name}.md              # Frontmatter + thin context dispatcher
│   └── {name}.lock.yml        # Auto-generated — NEVER edit manually
├── agents/
│   └── {name}.md              # Full agent persona (reusable)
└── aw/
    ├── actions-lock.json      # Action SHA pinning — commit this
    └── imports/               # Compile-time cache of cross-repo imports
```

`.github/workflows/shared/` is the convention for reusable components imported by multiple workflows. See [references/](references/) for local examples.

---

## Critical Patterns

### AGENTS.md Is the Source of Truth

Agent personas MUST NOT hardcode codebase layout, file paths, skill names, or project conventions. Point the agent at `AGENTS.md` files at runtime:

```markdown
Read `AGENTS.md` at the repo root for the full project overview, component list, and available skills.
```

For monorepos, include a routing table the agent uses to pick which component `AGENTS.md` to load. Never copy the contents of those files into the agent.

### Two-File Architecture

Workflow file = **config + context only**. Agent file = **all reasoning logic**. The workflow imports the agent and passes sanitized runtime context. Exception: thin reviewer workflows whose job is "apply skill X to artifact Y" can inline the prompt directly — don't create a persona that just restates a skill.

The `gh aw init` bootstrap also creates `.github/agents/agentic-workflows.agent.md`, which registers `/agent agentic-workflows` in Copilot Chat / VS Code Agent Mode for natural-language workflow management (`create`, `update`, `upgrade`, `import`, `debug`).

### Markdown body is hot-editable

Only the frontmatter drives compilation. The markdown BODY is loaded at runtime, so prompt edits can be pushed directly to `main` without running `gh aw compile`. Frontmatter edits require a recompile — the frontmatter-hash mismatch auto-files an issue at runtime.

### Sanitized Context (Security)

NEVER pass raw `github.event.issue.body` to the agent. Use the sanitized output:

```markdown
${{ steps.sanitized.outputs.text }}
```

The older form `${{ needs.activation.outputs.text }}` is DEPRECATED — the compiler rewrites it, but new workflows should use `steps.sanitized.*` directly. Sanitization neutralizes `@mentions`, `fixes #NNN`, XSS, ANSI escapes, caps at 0.5 MB / 65k lines.

### Read-Only Permissions + Safe Outputs

Workflows run read-only. Writes go through `safe-outputs`:

```yaml
permissions:
  contents: read
  issues: read
safe-outputs:
  add-comment:
    hide-older-comments: true
```

`id-token:` is a special case — it only accepts `write` or `none` (the compiler rejects `read`). Required for OIDC cloud auth (AWS/GCP/Azure); does NOT grant repo write.

NEVER put `${{ secrets.* }}` in top-level `env:` — strict mode makes it a compile error, non-strict a warning, because workflow-level env leaks to the agent container. Use `secrets:` (top-level) or engine-specific secret config.

### Strict Mode

`strict: true` (default) enforces: no write permissions, explicit network config, no wildcard domains, ecosystem identifiers required, SHA-pinned actions, no deprecated fields. `strict: false` workflows **FAIL AT RUNTIME on public repositories** — the error tells the operator to recompile in strict mode. Strict is per-workflow or global (`gh aw compile --strict`).

### Footer Control

```yaml
safe-outputs:
  messages:
    footer: "> 🤖 Generated by [{workflow_name}]({run_url}) [Experimental]"
  add-comment:
    footer: "if-body"  # skip footer when body is empty (clean approvals)
```

Variables: `{workflow_name}`, `{agentic_workflow_url}`, `{run_url}`, `{triggering_number}`, `{event_type}`, `{status}`, `{effective_tokens_suffix}`.

Even with `footer: false`, a hidden `<!-- gh-aw-workflow-id: NAME -->` marker remains in the body — search with `repo:owner/repo "gh-aw-workflow-id: my-workflow" in:body`.

`submit-pull-request-review.footer` accepts `"always" | "none" | "if-body"`.

### Markdown Body Scanner

The compiler scans markdown for zero-width / bidi unicode, hidden HTML (`<script>`, `<iframe>`, event handlers), JS/data URIs, URL shorteners, IP-based URLs, prompt-injection patterns, base64 shell commands, pipe-to-shell. These rejections CANNOT be overridden — keep prose plain.

---

## Imports

### Path Resolution (three modes)

```yaml
imports:
  - ../agents/my-agent.md                  # 1. Relative — resolves from importing file
  - .github/agents/shared.md               # 2. Repo-root — starts with .github/ or /
  - acme-org/ai-agents/agents/x.md@v2.0.0  # 3. Cross-repo — fetched at compile, cached by SHA
```

Append `#SectionName` to import one section. Prefix with `{{#import? file.md}}` for optional imports. Cross-repo imports live under `.github/aw/imports/` keyed by commit SHA.

### Parameterized Imports

Shared workflows declare a typed contract via `import-schema` and are called with `uses` + `with`:

```yaml
# Caller
imports:
  - uses: shared/deploy.md
    with:
      region: us-east-1
      languages: ["go", "typescript"]

# shared/deploy.md (no `on:` field)
import-schema:
  region: { type: string, required: true }
  environment: { type: choice, options: [staging, production], required: true }
  languages: { type: array, items: { type: string } }
```

Access values via `${{ github.aw.import-inputs.region }}` (dotted for objects). Types: `string`, `number`, `boolean`, `choice`, `array`, `object`. Importing the same file twice with different `with` values is a compile error; identical `with` is deduplicated.

### Runtime Imports (different from compile-time)

Inject file or URL content into the prompt at RUNTIME. Files must live under `.github/`:

```
{{#runtime-import coding-standards.md}}
{{#runtime-import? shared-instructions.md}}            — optional
{{#runtime-import docs/auth.go:45-52}}                 — line range
{{#runtime-import https://example.com/checklist.md}}   — URL, cached 1h at /tmp/gh-aw/url-cache/
```

Runtime imports REJECT `${{ }}` expressions in imported content (template-injection guard). Path traversal and absolute paths are blocked. No recursive imports. Processing order: runtime-import → expression interpolation → `{{#if}}`.

### `inlined-imports: true`

Set in frontmatter to embed ALL imported content into the compiled `.lock.yml`. REQUIRED for:

- **Cross-org `workflow_call`** — caller's `GITHUB_TOKEN` can't check out the platform repo's `.github`
- **Repository rulesets as required checks** — restricted runtime context, `ERR_SYSTEM: Runtime import file not found`

Trade-off: larger lock files, any import change requires recompile. Cannot combine with `.github/agents/` imports.

### Merge Semantics (BFS, earlier imports win)

| Field | Strategy |
|-------|----------|
| `tools` | Deep merge; `allowed` arrays concatenate + dedupe |
| `mcp-servers` | First-wins by name |
| `network.allowed` | Union, deduped, sorted |
| `permissions` | Validation only (NOT merged) — main must declare all imported perms at `write ≥ read ≥ none` |
| `safe-outputs` | Duplicate types across imports FAIL |
| `runtimes` | Main overrides imports |
| `services` | All merged; duplicate names fail |
| `steps` | Imported steps prepended in import order |
| `jobs` | NOT merged — define in main workflow only |

---

## Templating

### Allowed `${{ }}` expressions in the markdown body

Body expressions are restricted to prevent secret leakage to the LLM. Frontmatter has NO such restriction.

**Allowed:** `github.event.*` (issue/PR numbers, titles, SHAs), `github.actor`, `github.repository`, `github.owner`, `github.server_url`, `github.workspace`, `github.run_id`, `github.run_number`, `github.job`, `github.workflow`, `needs.*`, `steps.*`, `github.event.inputs.*`, `github.aw.inputs.*`, `github.aw.import-inputs.*`, `inputs.*`, `env.*`.

**Prohibited:** `secrets.*`, `vars.*`, `toJson()`, `fromJson()`, and anything not in the allowlist. Compile-time error.

### Conditional blocks

```
{{#if github.event.issue.number}}
Runs only when triggered by an issue.
{{/if}}
```

No nesting, no `else`, no loops. Falsy: `false`, `0`, `null`, `""`. The compiler wraps the expression in `${{ }}` automatically.

---

## Authentication

One engine secret is required before anything runs:

| Engine | Required secret | Notes |
|--------|----------------|-------|
| Copilot (default) | `COPILOT_GITHUB_TOKEN` | Fine-grained PAT, `Copilot Requests: Read`, resource owner MUST be a user |
| Claude | `ANTHROPIC_API_KEY` | `CLAUDE_CODE_OAUTH_TOKEN` is NOT supported |
| Codex | `OPENAI_API_KEY` (or `CODEX_API_KEY`) | |
| Gemini | `GEMINI_API_KEY` | |

Set with `gh aw secrets set NAME --value "..."`. Audit with `gh aw secrets bootstrap`.

### Magic secrets (auto-picked by name)

| Secret | Purpose |
|--------|---------|
| `GH_AW_GITHUB_TOKEN` | Generic fallback for GitHub auth |
| `GH_AW_GITHUB_MCP_SERVER_TOKEN` | Remote GitHub MCP server + projects toolsets |
| `GH_AW_AGENT_TOKEN` | `assign-to-agent` safe output (PAT only — GitHub App tokens rejected) |
| `GH_AW_CI_TRIGGER_TOKEN` | Triggers CI on agent-created PRs (see section below) |
| `GH_AW_PLUGINS_TOKEN` | APM package fetches |
| `GH_AW_READ_PROJECT_TOKEN` / `GH_AW_WRITE_PROJECT_TOKEN` | Split Projects tokens |

### GitHub App (recommended for org-wide)

One App covers all GitHub auth EXCEPT `COPILOT_GITHUB_TOKEN` (must remain a PAT) and `assign-to-agent` (Copilot assignment API rejects App tokens).

```yaml
tools:
  github:
    github-app:
      app-id: ${{ vars.APP_ID }}
      private-key: ${{ secrets.APP_PRIVATE_KEY }}
      repositories: ["*"]   # org-wide, or ["repo1","repo2"], or omit for current repo
```

Tokens are minted at job start matching `permissions:`, revoked at end.

### Projects auth

Default `GITHUB_TOKEN` CANNOT touch Projects. Required for `projects` toolset and `*-project` safe outputs. User projects need a classic PAT with `project` scope; org projects need a fine-grained PAT with `Projects: Read and write`.

---

## Tools

All agent capabilities are declared under `tools:` in frontmatter.

| Key | Purpose |
|-----|---------|
| `edit:` | File edits in workspace (required if the agent must modify files) |
| `github:` | GitHub API reads (see toolsets below) |
| `bash:` | Shell execution (see allowlist below) |
| `web-fetch:` | HTTP fetch |
| `web-search:` | Web search (Codex must opt in explicitly) |
| `playwright:` | Headless browser (see below) |
| `cache-memory:` | Cross-run file storage |
| `repo-memory:` | Git-backed persistent state |
| `agentic-workflows:` | Workflow introspection — requires `actions: read` |
| `timeout:` | Per-tool-call timeout seconds (Claude 60, Codex 120 default) |
| `startup-timeout:` | MCP init timeout (default 120) |

`mcp-servers:` and `mcp-scripts:` are SIBLINGS of `tools:`, not nested under it.

### GitHub toolsets

Default: `context, repos, issues, pull_requests, users`.

Available: `context`, `repos`, `issues`, `pull_requests`, `users`, `actions`, `code_security`, `discussions`, `labels`, `notifications`, `orgs`, `projects`, `gists`, `search`, `dependabot`, `experiments`, `secret_protection`, `security_advisories`, `stargazers`.

Shorthands: `default` (the 5) | `all` (everything except `dependabot` — opt in explicitly).

`tools.github.allowed-repos:` restricts reads to `"all"` | `"public"` | list with `owner/repo`, `owner/*`, `owner/prefix*`. Wildcards only at the end of repo-name.

`tools.github.mode: remote` uses GitHub's hosted MCP server and REQUIRES `github-token:` (or `GH_AW_GITHUB_MCP_SERVER_TOKEN`).

### Bash allowlist

```yaml
tools:
  bash:                              # default safe set: echo, ls, pwd, cat, head, tail, grep, wc, sort, uniq, date
  bash: []                           # disable all
  bash: ["poetry run pytest", "git status"]
  bash: ["git:*"]                    # wildcard family
  bash: [":*"]                       # unrestricted — AVOID
```

For Prowler workflows prefer explicit commands. Never use `[":*"]` on workflows that run on untrusted input (issues, fork PRs).

### MCP Scripts (inline custom tools)

Declare in frontmatter with four backends: `script:` (JS), `run:` (bash), `py:` (Python 3.10+), `go:`. Runs OUTSIDE the agent sandbox on the runner host — MUST be read-only.

```yaml
mcp-scripts:
  list-failing-checks:
    description: "List Prowler checks that failed in latest run"
    inputs:
      provider: { type: string, enum: ["aws","azure","gcp","kubernetes"], required: true }
    run: |
      jq '.[] | select(.status=="FAIL") | .check_id' "output/prowler-output-$INPUT_PROVIDER.json"
    env:
      GH_TOKEN: "${{ secrets.GITHUB_TOKEN }}"
    timeout: 120
```

Outputs over 500 chars are saved to a file and the path is returned. Secrets only via `env:`.

### MCP Servers

```yaml
network:
  allowed:
    - "mcp.prowler.com"

mcp-servers:
  prowler:
    url: "https://mcp.prowler.com/mcp"
    allowed:                         # least-privilege whitelist — strongly recommended
      - prowler_hub_get_check_details
      - prowler_docs_search
```

Transport options (use ONE): `command` + `args` (stdio — must be containerized), `container:` (explicit image), `url:` + `headers:` (HTTP), `registry:` (MCP registry URI, informational).

### Playwright

```yaml
tools:
  playwright:
    version: "1.56.1"     # or "latest"

network:
  allowed:
    - defaults
    - playwright          # REQUIRED to download browser binaries
    - "docs.prowler.com"  # subdomains auto-allowed
```

Without a `network:` block, Playwright is restricted to `localhost`/`127.0.0.1`.

### Checkout

```yaml
# Full history (git blame, changelog diff)
checkout:
  fetch-depth: 0

# Cross-repo multi-clone
checkout:
  - repository: prowler-cloud/other-repo
    path: ./libs/other
    github-token: ${{ secrets.CROSS_REPO_PAT }}
    current: true        # primary target (exactly one)

# No clone at all (pure MCP-based agent)
checkout: false
```

Key fields: `repository`, `ref`, `path`, `fetch-depth`, `fetch` (`"*"`, `"refs/pulls/open/*"`, globs), `sparse-checkout`, `submodules`, `lfs`, `github-token`/`github-app`. gh-aw enforces `persist-credentials: false` and passes auth via transient `http.extraheader`. Prefer this over a manual `actions/checkout` step.

### Service containers

`services:` exposes ports on the runner host, NOT inside the agent container. Connect from the agent using `host.docker.internal:<port>` instead of `localhost`.

---

## Trigger Patterns

### Shorthand cheat sheet

```yaml
on: push to master
on: push tags v*
on: pull_request opened affecting prowler/providers/**
on: pull_request merged
on: issue opened labeled prowler-bug
on: comment created
on: dependabot pull request
on: workflow completed ci-test
on: manual                  # = workflow_dispatch
on: api dispatch custom-event
on: /prowler-review         # slash command
```

All auto-include `workflow_dispatch`. Invalid globs (`./src/**`, spaces, unclosed brackets) fail at compile time.

### Pre-activation steps (deterministic gating)

Run cheap deterministic checks in the activation job BEFORE the expensive agent job. Each step with an `id` auto-exports `<id>_result` (success/failure/cancelled/skipped).

```yaml
on:
  issues:
    types: [opened]
  permissions:
    issues: read
  steps:
    - name: Check label
      id: label_check
      env:
        LABELS: ${{ toJSON(github.event.issue.labels.*.name) }}
      run: echo "$LABELS" | grep -q '"prowler-bug"'
if: needs.pre_activation.outputs.label_check_result == 'success'
```

Saves an entire job vs. a separate custom filter workflow.

### Skip conditions (cost control)

```yaml
on: daily
  skip-if-match: 'is:issue is:open in:title "[prowler-daily]"'   # skip if dup exists

on: weekly on monday
  skip-if-no-match:
    query: "is:pr is:open label:needs-prowler-review"
    min: 1    # only run if there's work to do
```

Default scope is current repo; use `scope: none` + `on.github-token`/`github-app` for org-wide queries.

### `stop-after:` (budget cutoff)

```yaml
on: weekly on monday
  stop-after: "+30d"     # or an absolute date
```

Minimum hours. Recompile resets the clock.

### Fork filtering

PR triggers **BLOCK FORKS BY DEFAULT**. Opt in explicitly via repository IDs (rename-safe):

```yaml
on:
  pull_request:
    types: [opened, synchronize]
    forks: ["prowler-cloud/*"]    # or ["owner/repo"] or ["*"] (dangerous)
```

### Manual approval gate

```yaml
on:
  workflow_dispatch:
  manual-approval: production    # must match an Environment with reviewers configured
```

Different from `workflow_dispatch.type: environment` (which is just a dropdown, no enforcement).

### Slash & label commands

```yaml
on:
  slash_command:
    name: ["prowler-review", "pr-review", "review"]
    events: [pull_request, pull_request_comment]   # restrict surface

  label_command:
    name: prowler-scan
    events: [pull_request]
    remove_label: false                             # default true (one-shot)
```

Matched value available as `needs.activation.outputs.slash_command` / `label_command`. Slash commands conflict with `issues`/`issue_comment`/`pull_request` unless those use label-only types.

### `workflow_run` triggers REQUIRE `branches:`

```yaml
on:
  workflow_run:
    workflows: ["CI"]
    types: [completed]
    branches: [master]    # mandatory — compiler warns without it, strict mode errors
```

Compiler injects repo-ID / fork validation automatically.

### Status comments & reactions

`reaction: "eyes"` only adds the emoji. `status-comment: true` must be set EXPLICITLY for `slash_command`/`label_command` triggers to post "started" → "completed" comments with the run link.

### `lock-for-agent:`

`on.issues.lock-for-agent: true` locks the issue at activation, unlocks via `always()`. Requires `issues: write`. Silently skipped on PRs.

---

## Schedule Patterns

Prefer FUZZY schedules over raw cron. The compiler deterministically scatters execution times per workflow path, preventing load spikes. Compiler WARNS on fixed-minute cron patterns.

```yaml
on: daily                                  # scattered time
on: daily around 14:00                     # ±1 hour window
on: daily between 9:00 and 17:00 on weekdays
on: hourly on weekdays
on: every 2h                               # scattered minute
on: weekly on monday around 9am
on: bi-weekly                              # also tri-weekly
```

Time formats: `HH:MM`, `1am`–`12pm`, `midnight`, `noon`.
Inline timezone: `daily around 9am utc-5` (`utc+N`, `utc-N`, `utc+HH:MM`).
Cron form timezone: `timezone: "America/New_York"` (full IANA, DST-aware).

```yaml
on:
  schedule:
    - cron: "30 9 * * 1-5"
      timezone: "America/New_York"
```

Minimum interval: 5 minutes (GitHub Actions). Valid: `5m`, `10m`, `15m`, `20m`, `30m`, `1h`, `2h`, `3h`, `4h`, `6h`, `8h`, `12h`. Shorthand `on: daily` auto-includes `workflow_dispatch`.

---

## Network Allowlist

### Ecosystem identifiers

| ID | Covers |
|----|--------|
| `defaults` | Certs, JSON schema, Ubuntu mirrors (baseline) |
| `github` | github.com, *.githubusercontent.com, docs.github.com, github.blog |
| `local` | localhost, 127.0.0.1, ::1 |
| `default-safe-outputs` | Compound: defaults + dev-tools + github + local |
| `dev-tools` | Codecov, Shields.io, Snyk, Renovate, CircleCI |
| `containers` | Docker Hub, GHCR, Quay, GCR |
| `linux-distros` | Debian, Alpine |
| `playwright`, `chrome`, `terraform`, `deno` | Tool-specific |
| Languages | `python`, `node`, `go`, `rust`, `dotnet`, `java`, `ruby`, `php`, `swift`, `kotlin` (+`java`), `dart`, `haskell`, `julia`, `perl`, `ocaml` |

Prowler is Python-first → `[defaults, python, github]` is the sane baseline.

Strict mode WARNS (but allows) when you list individual ecosystem domains like `pypi.org`; use `python`/`node` instead. Custom non-ecosystem domains (`api.example.com`) are NOT warned. Subdomains match automatically. Wildcards: one leading `*` only.

### Blocked list

`blocked:` takes precedence over `allowed:` and includes subdomains.

### Firewall extended config

```yaml
network:
  firewall:
    log-level: info        # debug | info | warn | error
    ssl-bump: true         # HTTPS deep inspection (AWF ≥ 0.9.0) — MITM, enable carefully
    allow-urls:
      - "https://api.github.com/repos/*/issues"
  allowed: [defaults, python]
```

### Protocol filtering

`"https://secure.api.example.com"` / `"http://legacy.example.com"` restrict by protocol (Copilot + Claude with AWF).

`network: {}` denies all; omitting `network:` defaults to `defaults`.

---

## Security Hardening

### Defense-in-Depth Layers

| Layer | How | Why |
|-------|-----|-----|
| **Read-only permissions** | Only `read` in `permissions:` | Agent never gets write access |
| **Safe outputs** | Declare writes in `safe-outputs:` | Writes happen in separate jobs with scoped permissions |
| **Sanitized context** | `${{ steps.sanitized.outputs.text }}` | Prevents prompt injection from raw issue/PR body |
| **Explicit network** | List ecosystem IDs in `network.allowed:` | AWF firewall blocks all other egress |
| **Tool allowlisting** | `allowed:` in each `mcp-servers:` entry | Restricts which MCP tools the agent can call |
| **Concurrency** | `concurrency:` with `cancel-in-progress: true` | Prevents race conditions on same trigger |
| **Rate limiting** | `rate-limit:` with `max` and `window` | Prevents abuse via rapid re-triggering |
| **Integrity filtering** | `tools.github.min-integrity: approved` | Filters GitHub content by author trust (replaces deprecated `lockdown:`) |
| **Threat detection** | Custom `prompt` under `safe-outputs.threat-detection:` | AI scans agent output before writes execute |
| **Protected files** | `protected-files: blocked` (default) on PR writes | Blocks patches to dependency manifests, agent files, CODEOWNERS |
| **Fork filtering** | `forks:` allowlist on `pull_request` | PR triggers block forks by default |

### Sandbox Architecture (AWF)

Default: `sandbox.agent: awf` (Agent Workflow Firewall). The coding agent runs inside a container; the MCP gateway is always on and cannot be disabled.

- Filesystem: `$HOME`, `$GITHUB_WORKSPACE`, `/tmp` are RW; `/usr`, `/opt`, `/bin`, `/lib` are read-only
- **Docker socket is hidden** — agents cannot spawn containers
- All host binaries and env vars are available inside the sandbox (`AWF_HOST_PATH` preserves setup-action tools)
- macOS and Windows runners NOT supported (no nested virt for containers)
- Network egress controlled via top-level `network:` with `firewall: true`

### Integrity Filtering (replaces Lockdown Mode)

`lockdown:` is DEPRECATED. Use `tools.github.min-integrity` instead. No `GH_AW_GITHUB_TOKEN` or additional auth required.

Migration:
- `lockdown: true` → `min-integrity: approved`
- `lockdown: false` → `min-integrity: none`

Integrity hierarchy (high → low): `merged > approved > unapproved > none > blocked`.

| Level | Who qualifies |
|-------|---------------|
| `merged` | Merged PRs; commits on default branch (any author) |
| `approved` | `OWNER`/`MEMBER`/`COLLABORATOR`; non-fork PRs on public repos; all items in private repos; trusted bots (dependabot, github-actions) |
| `unapproved` | `CONTRIBUTOR`, `FIRST_TIME_CONTRIBUTOR` |
| `none` | Everyone including `NONE` association |
| `blocked` | Users in `blocked-users` (deny list, not a valid `min-integrity` value) |

```yaml
tools:
  github:
    min-integrity: approved
    blocked-users: ["spam-bot"]
    approval-labels: ["human-reviewed"]   # promotes labeled items to approved
```

**Public repos default to `min-integrity: approved` even if unset. Private/internal repos default to NO guard policy — all content accessible.**

Filtered items logged as `DIFC_FILTERED` in `gateway.jsonl`; inspect with `gh aw logs --filtered-integrity`.

### DIFC Proxy

`tools.github.min-integrity: approved` auto-enables a DIFC (Data Integrity Flow Control) proxy around the agent that enforces integrity at the network boundary ON TOP OF the gateway's filtering. Opt out with `tools.github.integrity-proxy: false`. The deprecated `features.difc-proxy:` flag is replaced by this.

### Fork Support

Two distinct scenarios:

1. **Workflow running inside a fork** — auto-skipped via injected `if: ${{ !github.event.repository.fork }}`. Intentional; no safe partial config.
2. **Inbound PRs from forks** — blocked by default via repo-ID check. Allow trusted forks with `on.pull_request.forks:` (see Trigger Patterns).

### Protected Files (Supply-Chain Defense)

Enabled by default for `create-pull-request` and `push-to-pull-request-branch`. Blocks patches touching:

- Dependency manifests: `package.json`, `go.mod`, `requirements.txt`, `Gemfile`, `pom.xml`, `Cargo.toml`, uv/Bun/Deno/.NET/Elixir/Haskell
- Agent instruction files: `AGENTS.md`, `CLAUDE.md` + `.claude/`, `.codex/`
- `.github/**` and `.agents/**`
- `CODEOWNERS` at root, `.github/`, `docs/`

```yaml
safe-outputs:
  create-pull-request:
    protected-files: fallback-to-issue    # blocked (default) | allowed | fallback-to-issue
    excluded-files: ["**/*.lock", "dist/**"]    # strip these from the patch
```

`push-to-pull-request-branch` CANNOT push to fork PRs (security).

### Threat Detection

Nested UNDER `safe-outputs:` (NOT top-level). Auto-enabled when safe-outputs exist. Full fields:

| Field | Purpose |
|-------|---------|
| `enabled` | bool, default `true` |
| `prompt` | Custom analysis instructions appended to default |
| `engine` | Override engine; `false` disables AI, runs only custom steps |
| `runs-on` | Runner for detection job |
| `steps` | Pre-steps before AI (setup, gateway auth) |
| `post-steps` | Post-steps after AI (scanners, reporting) |

Execution order: download artifacts → `steps:` → AI → `post-steps:` → upload log. Artifacts at `/tmp/gh-aw/threat-detection/`: `prompt.txt`, `agent_output.json`, `aw.patch`. AI schema: `{prompt_injection, secret_leak, malicious_patch, reasons[]}`. Any `true` blocks safe outputs.

For comment-only workflows the AI prompt is sufficient — don't add TruffleHog/Semgrep steps unless the workflow generates files.

### Harden-Runner Coverage (Known Limitation)

`steps:` in frontmatter injects pre-steps into the **agent job only**. The compiled `.lock.yml` contains 5–6 framework jobs (`pre_activation`, `activation`, `detection`, `safe_outputs`, `conclusion`) NOT covered. As of gh-aw v0.67.1 there is NO global hardening mechanism — no top-level `harden-runner:`, no CLI flag, no config file.

```yaml
steps:
  - name: Harden Runner
    uses: step-security/harden-runner@fa2e9d605c4eeb9fcad4c99c224cee0c6c7f3594 # v2.16.0
    with:
      egress-policy: audit    # or block + allowed-endpoints once footprint is known
```

**Do NOT patch the generated `.lock.yml` by hand.** Every `gh aw compile` wipes manual edits. If full-job hardening matters, file upstream at `github/gh-aw`.

The `safe_outputs` job (the one with write permissions) runs on `ubuntu-slim`, calls only GitHub APIs — narrow egress but still a defense-in-depth hole.

### Compilation Security Scanners

```bash
gh aw compile --actionlint --zizmor --poutine
```

- **actionlint**: Workflow linting (shellcheck, pyflakes)
- **zizmor**: Security vulnerabilities, privilege escalation
- **poutine**: Supply chain risks, third-party action trust

Findings in the auto-generated `.lock.yml` from gh-aw internals can be ignored. Only act on findings in YOUR workflow configuration.

---

## Safe Outputs

Safe outputs enforce privilege separation: the agent job runs read-only and writes a structured JSON file. A second job (auto-generated) reads that file and executes the writes with scoped permissions (`issues: write`, etc.). The agent never sees a write token. **This is the defense against prompt injection.**

### ⚠️ The `noop` trap

If the agent finishes WITHOUT calling any safe-output tool, the workflow **fails silently with no output**. This is the #1 runtime failure mode. Always instruct the agent to call `noop` when its analysis concludes no action is needed. `noop` is auto-enabled.

### Quick Reference (20 most-used types)

**Issues & comments**

| Type | Purpose | Default max |
|------|---------|-------------|
| `create-issue` | File a new issue | 1 |
| `update-issue` | Change status, title, body | 1 |
| `close-issue` | Close with comment | 1 |
| `link-sub-issue` | Attach as sub-issue | 1 |
| `add-comment` | Comment on issue/PR/discussion | 1 |
| `hide-comment` | Minimize (outdated/spam/abuse/off_topic/resolved) | 5 |

**Labels & routing**

| Type | Purpose | Default max |
|------|---------|-------------|
| `add-labels` / `remove-labels` | Label management | 3 |
| `add-reviewer` | Request reviewers (supports `copilot`) | 3 |
| `assign-to-user` / `unassign-from-user` | User assignment | 1 |
| `assign-to-agent` | Hand off to Copilot coding agent | 1 |
| `assign-milestone` | Milestone assignment | 1 |

**Pull requests (code writes)**

| Type | Purpose | Default max |
|------|---------|-------------|
| `create-pull-request` | Open PR from agent patch | 1 |
| `update-pull-request` | Update title/body | 1 |
| `push-to-pull-request-branch` | Push commits to existing PR (same-repo only) | 1 |
| `create-pull-request-review-comment` | Inline review comment on a line | 10 |
| `submit-pull-request-review` | Submit APPROVE/REQUEST_CHANGES/COMMENT review | 1 |
| `resolve-pull-request-review-thread` | Resolve a thread | 10 |

**Security, dispatch, assets**

| Type | Purpose | Default max |
|------|---------|-------------|
| `create-code-scanning-alert` | Emit SARIF advisory (same-repo) | unlimited |
| `dispatch-workflow` | Trigger another workflow with inputs | 3 |
| `upload-asset` | Commit file to orphaned branch, return raw URL | 10 |

**System (auto-enabled)**

| Type | When |
|------|------|
| `noop` | MUST be called when no action needed — see warning above |
| `missing-tool` | Agent reports a missing capability |
| `missing-data` | Agent reports missing inputs |

### Shared options

- `max: N` — hard cap per run
- `target: "triggering" | "*" | <number>` — restrict target item (`"*"` requires agent to supply `issue_number`/`pull_request_number`)
- `target-repo: "owner/repo"` + `allowed-repos: [...]` — cross-repo execution
- `github-token: ${{ secrets.CUSTOM }}` — override default token
- `footer: false | "if-body" | "always" | "none"` — attribution footer control
- `hide-older-comments: true` — minimize prior comments from the same workflow (on `add-comment`)
- `staged: true` — preview mode (see Staged Mode section)

### `assign-to-agent`

Programmatically assign the Copilot coding agent to EXISTING issues/PRs. For new issues use `assignees: copilot` in `create-issue`.

```yaml
safe-outputs:
  assign-to-agent:
    name: "copilot"
    target: "triggering"
    github-token: ${{ secrets.GH_AW_AGENT_TOKEN }}
```

Requires a fine-grained PAT (Actions/Contents/Issues/PRs all Write). **GitHub App tokens are REJECTED** by the Copilot assignment API.

---

## Custom Safe Outputs

Built-in types cover GitHub. For Slack/Jira/Notion/databases/any third-party write, use one of three mechanisms under `safe-outputs:`:

| Mechanism | Runs where | Secrets | Use when |
|-----------|-----------|---------|----------|
| `safe-outputs.scripts` | In-process | No | Lightweight JS (transform, noop-style) |
| `safe-outputs.actions` | Step in safe-outputs job | Yes (via `env:`) | Mount an existing marketplace action as a single MCP tool |
| `safe-outputs.jobs` | Separate GitHub Actions job | Yes (full) | External API calls needing secrets, multi-step work |

```yaml
safe-outputs:
  jobs:
    slack-notify:
      description: "Send a message to Slack"
      runs-on: ubuntu-latest
      inputs:
        message: { type: string, required: true }
      steps:
        - env:
            SLACK_WEBHOOK: "${{ secrets.SLACK_WEBHOOK }}"
          run: |
            MESSAGE=$(jq -r '.items[] | select(.type=="slack_notify") | .message' "$GH_AW_AGENT_OUTPUT")
            curl -X POST "$SLACK_WEBHOOK" -H 'Content-Type: application/json' \
              -d "$(jq -n --arg t "$MESSAGE" '{text:$t}')"
```

Rules:
- Dashes in names normalize to underscores when exposed as MCP tools (`slack-notify` → `slack_notify`)
- Every custom job MUST declare `description` + `inputs`
- Agent data arrives via `GH_AW_AGENT_OUTPUT` (path to JSON with `{"items": [{"type":"<normalized>", ...}]}`)
- `needs:` in job frontmatter orders against built-ins (`agent`, `safe_outputs`, `detection`, `upload_assets`, `unlock`)
- `GH_AW_SAFE_OUTPUTS_STAGED === "true"` → skip real write, emit `core.summary` preview
- Use `core.setFailed()` for errors; validate secrets up front

Place shared definitions in `.github/workflows/shared/` and import them.

---

## Cross-Repository Operations

Three independent mechanisms, each needs its own auth. Default `GITHUB_TOKEN` only sees the current repo.

### 1. Checkout — clone other repos into workspace

```yaml
checkout:
  - repository: org/other
    path: ./libs/other
    github-token: ${{ secrets.CROSS_REPO_PAT }}
    current: true    # primary target for agent GitHub operations
```

### 2. Reading — GitHub tools with custom token

```yaml
tools:
  github:
    toolsets: [repos, issues, pull_requests]
    github-token: ${{ secrets.CROSS_REPO_PAT }}    # or use GH_AW_GITHUB_MCP_SERVER_TOKEN
```

Enables reading issues/PRs/code/releases from private repos without checkout.

### 3. Safe outputs — write to external repos

```yaml
safe-outputs:
  github-token: ${{ secrets.CROSS_REPO_PAT }}
  create-issue:
    target-repo: "org/tracker"          # single target
  create-pull-request:
    target-repo: "*"                    # agent picks at runtime via `repo` param
    allowed-repos: ["org/a", "org/b"]
```

`target-repo: "*"` NOT supported by: `create-pull-request-review-comment`, `reply-to-pull-request-review-comment`, `submit-pull-request-review`, `create-agent-session`, `manage-project-items`. Current repo always implicitly allowed.

**#1 failure mode for cross-org `workflow_call`** — caller's `GITHUB_TOKEN` can't check out the platform repo's `.github`. Fix: `inlined-imports: true` on the callee (see Imports).

---

## Triggering CI on agent-created PRs

PRs created with the default `GITHUB_TOKEN` DO NOT trigger CI (Actions cascade guard). Set the magic secret:

```bash
gh aw secrets set GH_AW_CI_TRIGGER_TOKEN --value "<PAT with contents:write>"
```

gh-aw pushes an extra empty commit with this token, triggering `push`/`pull_request` events. Alternatives: `github-token-for-extra-empty-commit: app` (GitHub App) or `github-token: ${{ secrets.PAT }}` (full override — changes PR author).

Applies to `create-pull-request` AND `push-to-pull-request-branch`.

---

## Concurrency Control

gh-aw applies concurrency at TWO levels automatically:

- **Per-workflow** — group derived from workflow name + context (issue/PR/ref)
- **Per-engine** — `gh-aw-{engine-id}`, only one agent job per engine across ALL workflows (prevents AI resource exhaustion)

| Trigger | `cancel-in-progress` |
|---------|----------------------|
| Issues | No |
| Pull Requests | **Yes** — new commits cancel prior runs |
| Push | No |
| Schedule | No |
| Label-triggered | Yes for PRs, No otherwise (group includes label name) |

Override either level:

```yaml
concurrency:
  group: custom-${{ github.ref }}
  cancel-in-progress: true
engine:
  id: copilot
  concurrency:
    group: "gh-aw-copilot-${{ github.workflow }}"
```

### Fan-out pattern

When dispatching many runs with different inputs, the compiler-generated job groups are static and cancel each other. Use `concurrency.job-discriminator` to make each unique:

```yaml
concurrency:
  job-discriminator: ${{ inputs.finding_id }}
```

No effect on `workflow_dispatch`-only, `push`, `pull_request`. Stripped from compiled lock file.

Safe-outputs concurrency: `safe-outputs.concurrency-group` serializes issue/PR creation with `cancel-in-progress: false`.

---

## Rate Limiting

```yaml
rate-limit:
  max: 5                                   # required: 1–10
  window: 60                               # minutes, default 60, max 180
  events: [workflow_dispatch, issue_comment]   # auto-inferred if omitted
  ignored-roles: [admin, maintain]         # default; set [] to rate-limit admins too
```

The pre-activation job counts recent runs and cancels if the limit is exceeded.

### Defense-in-depth stack (combine for high-risk workflows)

- `rate-limit` — per-user throttle
- `concurrency` — serialize execution
- `timeout-minutes` — agent step cap (default 20 min)
- `stop-after: +48h` — absolute cutoff
- `safe-outputs.*.max` — cap write operations
- Hardcoded delays: 10s between agent assignments, 5s between workflow dispatches (not disableable)
- `safe-outputs.*.environment: production` — manual approval via GitHub Environments

`github-actions[bot]` does NOT trigger workflow events — prevents loops from safe outputs.

---

## AI Engines

Four supported engines. Specify as a string for defaults (`engine: copilot`) or as a block for extended config.

| Engine | `id` | Notes |
|--------|------|-------|
| GitHub Copilot | `copilot` | Default. Supports Copilot Custom Agents via `engine.agent`, `max-continuations` budget |
| Anthropic Claude | `claude` | `max-turns` iteration budget, `tools.timeout` per tool call |
| OpenAI Codex | `codex` | No `max-turns` — rely on `tools.timeout` + `timeout-minutes` |
| Google Gemini | `gemini` | No `max-turns` or `max-continuations` — use `timeout-minutes` + `tools.timeout` |

### Extended Engine Block

```yaml
engine:
  id: copilot
  version: "0.0.422"           # pin for reproducibility; accepts expressions
  model: gpt-5                 # engine-specific model selector
  agent: technical-doc-writer  # Copilot only — maps to .github/agents/{name}.agent.md
  api-target: api.acme.ghe.com # GHES/GHEC/internal proxy
  args: ["--add-dir", "/workspace", "--verbose"]
  command: /usr/local/bin/copilot-dev
  env:
    DEBUG_MODE: "true"
    ANTHROPIC_BASE_URL: "https://anthropic-proxy.internal.example.com"
    ANTHROPIC_API_KEY: ${{ secrets.PROXY_API_KEY }}
```

When using `api-target` or env-var endpoints (`OPENAI_BASE_URL`, `ANTHROPIC_BASE_URL`, `GITHUB_COPILOT_BASE_URL`), add the target domain to `network.allowed`.

### Timeouts (multi-level)

| Level | Field | Applies to | Default |
|-------|-------|-----------|---------|
| Job | `timeout-minutes:` (top-level) | Wall clock for the agent job | 20 min |
| Per tool call | `tools.timeout:` (seconds) | Each tool invocation | Claude 60s, Codex 120s |
| Iteration | `max-turns:` (Claude) / `max-continuations:` (Copilot) | Agent reasoning budget | Engine-specific |

### Token Weights

Override cost multipliers for custom or non-standard models. Baseline is Claude Sonnet 4.5 = 1.0:

```yaml
engine:
  id: claude
  token-weights:
    multipliers:
      my-custom-model: 2.5
    token-class-weights:
      output: 6.0
      cached-input: 0.05
```

### Org-wide model overrides (env vars)

Frontmatter wins; these are fallbacks:

- `GH_AW_MODEL_AGENT_{COPILOT,CLAUDE,CODEX,GEMINI,CUSTOM}` — main agent
- `GH_AW_MODEL_DETECTION_{COPILOT,CLAUDE,CODEX,GEMINI}` — threat detection

---

## Cost Management

Cost = **GitHub Actions minutes** + **inference costs** (billed by the AI provider).

- **Copilot**: premium requests charged to the account owning `COPILOT_GITHUB_TOKEN` (NOT the repo/org) — use a service account for per-workflow attribution
- **Claude/Codex/Gemini**: per-token billing on the corresponding API key's account

Per run: pre-activation ~10–30s + agent 1–15 min + ~1.5 min runner overhead per job.

### Observability

```bash
gh aw logs                                      # overview: duration, tokens, cost
gh aw logs --engine copilot --start-date -30d
gh aw logs --start-date -30d --json             # scriptable: .runs[].duration / .token_usage / .estimated_cost
gh aw audit <run-id>                            # single-run deep dive
gh aw logs --format markdown <workflow>         # cross-run trends + anomaly detection
```

For orchestrated workflows JSON also includes `.episodes[]` rollups with `total_runs`, `total_tokens`, `total_estimated_cost`, `risky_node_count`.

### Trigger cost risk

`push`, `check_run`, `check_suite` are HIGH risk in active repos (hundreds of runs/day). Start with `schedule` or `workflow_dispatch`, then move to event-based triggers with safeguards.

### Reducing spend (in order)

1. **Skip before the agent runs** — `skip-if-match` / `skip-if-no-match` evaluated in low-cost pre-activation, cancels before inference
2. **Cheaper models** for routine tasks (`gpt-4.1-mini`, `claude-haiku-4-5`); reserve frontier models for complex work
3. **Trim context** — focused prompts, avoid whole-file reads, cap list results
4. **`rate-limit` + `concurrency`** — serialize and throttle
5. **Schedules for predictable budgets** — `schedule: daily on weekdays` = 5 runs/week

### Self-optimizing meta-agents

```yaml
permissions:
  actions: read
tools:
  agentic-workflows:
```

A scheduled meta-agent can fetch cost data, identify expensive workflows, and open PRs switching to smaller models or tightening `skip-if-match`.

---

## Token Accounting (Effective Tokens)

gh-aw normalizes LLM token usage into **Effective Tokens (ET)** — a scalar comparable across token classes, models, and multi-agent graphs. Used by `gh aw logs` / `gh aw audit`.

Default weights: input `1.0`, cached input `0.1`, output `4.0`, reasoning `4.0`.

```
ET_total = Σ [ m_i × (I + 0.1·C + 4·O + 4·R) ]
```

where `m_i` is the model's Copilot multiplier. Cached input is 40× cheaper than output — **prompt caching is the highest-leverage ET optimization**.

Sub-agent invocations reference their triggering invocation as `parent_id` and are aggregated into the root's total.

---

## Cache Memory (cross-run file storage)

Persistent file storage via GitHub Actions cache. 7-day retention, 10 GB per repo, LRU eviction.

```yaml
tools:
  cache-memory: true
```

Mounts at `/tmp/gh-aw/cache-memory/`. Default key: `memory-${{ github.workflow }}-${{ github.run_id }}`.

### Advanced

```yaml
tools:
  cache-memory:
    key: custom-memory-${{ github.workflow }}-${{ github.run_id }}
    retention-days: 30                           # 1–90 (uploads as artifact)
    allowed-extensions: [".json", ".txt", ".md"]
```

**Progressive restore**: keys split on dashes. `custom-memory-project-v1-${run_id}` tries in order: `custom-memory-project-v1-`, `custom-memory-project-`, `custom-memory-`, `custom-`. Design keys hierarchically for maximum hits.

### Multiple caches

```yaml
tools:
  cache-memory:
    - id: default
      key: memory-default
    - id: session
      key: memory-session-${{ github.run_id }}
```

Additional caches mount at `/tmp/gh-aw/cache-memory-{id}/`.

### Integrity-aware caching

When `tools.github.min-integrity` is set, cache-memory uses git-backed branch isolation per integrity level. Higher-integrity always wins merge conflicts. Prevents a lower-integrity agent from poisoning data a higher-integrity run later reads.

With threat detection enabled, cache saves only AFTER validation: restore → modify → upload artifact → validate → save. **Never store secrets in cache memory.**

---

## Repo Memory (git-backed persistent state)

Unlimited-retention file storage via orphan Git branches. Version-controlled, auto-committed.

```yaml
tools:
  repo-memory: true
```

Creates branch `memory/default`, mounts at `/tmp/gh-aw/repo-memory-default/`.

```yaml
tools:
  repo-memory:
    branch-name: memory/custom-agent
    file-glob: ["*.md", "*.json"]
    max-file-size: 1048576       # default 10 KB
    max-file-count: 50           # default 100
    max-patch-size: 102400       # default 10 KB, max 100 KB — TOTAL diff cap
    target-repo: "owner/repo"    # isolate to another repo
```

**Conflict resolution: `pull -X ours` — your changes always win.** Read before writing to avoid overwriting prior state. Patches exceeding `max-patch-size` are rejected (protects against runaway memory growth).

### Cache Memory vs Repo Memory

| Feature | Cache Memory | Repo Memory |
|---------|-------------|-------------|
| Storage | Actions Cache | Git Branches |
| Retention | 7 days | Unlimited |
| Size Limit | 10 GB/repo | Repo limits |
| Version Control | No | Yes |
| Performance | Fast | Slower |
| Best For | Sessions | Long-term history |

---

## Environment Variables

gh-aw supports `env:` at 13 scopes. Most-specific-wins.

**Standard**: `env:` (workflow) → `jobs.<id>.env` → `steps[*].env`.

**gh-aw-specific** (independent chains): `engine.env`, `container.env`, `services.<id>.env`, `sandbox.agent.env`, `sandbox.mcp.env`, `tools.<name>.env`, `mcp-scripts.<name>.env`, `safe-outputs.env` (global) → `safe-outputs.jobs.<name>.env`.

### System-injected runtime vars (read-only)

| Variable | Value |
|----------|-------|
| `GITHUB_AW` | `"true"` — agents can check they're in a gh-aw workflow |
| `GH_AW_PHASE` | `"agent"` or `"detection"` |
| `GH_AW_VERSION` | Compiler version |
| `GH_AW_PROMPT` | `/tmp/gh-aw/aw-prompts/prompt.txt` |

### `GITHUB_STEP_SUMMARY`

Inside the sandbox, redirected to `/tmp/gh-aw/agent-step-summary.md`. **First 2000 chars** appended to the real summary after secret redaction. Write important content first.

### CLI config env

- `DEBUG=cli:*,workflow:*` — namespace debug logging
- `GH_AW_FEATURES` — comma-separated experimental flags
- `GH_AW_MAX_CONCURRENT_DOWNLOADS` (1–100, default 10) for `gh aw logs`
- `NO_COLOR`, `ACCESSIBLE`

---

## Runtimes

The compiler auto-detects runtime needs from `bash:` allowlist and workflow steps. Defaults: `node=24`, `python=3.12`, `go=1.25`, `uv=latest`, `bun=1.1`, `deno=2.x`, `ruby=3.3`, `java=21`, `dotnet=8.0`, `elixir=1.17`, `haskell=9.10`.

```yaml
runtimes:
  python:
    version: "3.11"
    action-repo: actions/setup-python
    action-version: v5
```

Runtimes from imported workflows merge automatically.

---

## Commands

```bash
# Compile
gh aw compile                                 # all workflows
gh aw compile <workflow>
gh aw compile --strict                        # strict validation
gh aw compile --no-emit                       # validate without writing .lock.yml
gh aw compile --actionlint --zizmor --poutine # full security scan
gh aw compile --purge                         # remove orphaned .lock.yml files
gh aw compile --dependabot                    # generate dep manifests + dependabot.yml
gh aw compile --action-mode action --actions-repo owner/repo --action-tag <ref>

# Validate (compile + all linters, no output)
gh aw validate
gh aw validate --json --strict

# Lifecycle
gh aw update-actions                          # refresh actions-lock.json SHA pins
gh aw upgrade                                 # tooling: self-update + codemods + recompile
gh aw update                                  # content: pull workflow .md from source repo

# Runtime
gh aw status                                  # list all workflows, filter with --label
gh aw add owner/repo/workflow.md              # install from upstream
gh aw run workflow-name                       # manual trigger
gh aw logs [workflow-name] --format markdown --count 10

# Audit & forensics
gh aw audit <run-id-or-url>                   # accepts run ID, run URL, job URL, step URL
gh aw audit <run-id> --parse                  # emit log.md + firewall.md
gh aw audit <run-id> --json -o ./audit
gh aw audit diff <base> <comp> [<comp>...]    # behavioral diff: new domains, allow↔deny, MCP tool deltas, token/duration metrics

# Secrets
gh aw secrets set NAME --value "..."
gh aw secrets bootstrap                       # audit required secrets

# Fix codemods (migrate deprecated fields)
gh aw fix <workflow> --write
```

---

## Compilation Pipeline

`gh aw compile` runs five phases:

1. **Parse & Validate** — extract frontmatter, validate schema, resolve `imports:` via BFS, merge by field-specific strategies
2. **Job Construction** — builds `pre_activation`, `activation`, `agent`, `detection`, safe-output jobs, `conclusion`
3. **Dependency Resolution** — topological sort, circular-ref detection, Mermaid graph
4. **Action Pinning** — resolves `action@version` → commit SHA via `.github/aw/actions-lock.json` cache → GitHub API → embedded pins
5. **YAML Generation** — emits `.lock.yml` with `# gh-aw-metadata:` first-line header, Mermaid graph, alphabetical jobs, embedded prompt

**Always commit `.github/aw/actions-lock.json`** — without it, compilation under restricted tokens (Copilot Coding Agent, Copilot Chat MCP) fails.

Only the frontmatter drives compilation. Markdown body edits do NOT require recompile — the frontmatter-hash mismatch auto-files an issue at runtime when detected.

---

## Staged Mode

Preview safe outputs without executing them.

```yaml
safe-outputs:
  staged: true               # applies to all outputs
  create-pull-request:
    staged: true             # or per-output
```

Runs the full workflow including AI, but suppresses every write. A preview with a 🎭 indicator is rendered in the Actions step summary. Custom safe-output jobs receive `GH_AW_SAFE_OUTPUTS_STAGED=true` and must branch on it.

**Recommended flow for new workflows**: start staged → trigger on a real event → review summary → tune prompt → remove `staged` when stable.

---

## Dependencies (APM)

The old `dependencies:` frontmatter field is DEPRECATED. Use the Microsoft APM package manager via import:

```yaml
imports:
  - uses: shared/apm.md
    with:
      packages:
        - microsoft/apm-sample-package
        - github/awesome-copilot/skills/review-and-refactor
        - microsoft/apm-sample-package#v2.0    # tag/branch/SHA pin
```

Package refs: `owner/repo`, `owner/repo/path/to/primitive`, `owner/repo#ref`. An `apm` job packs packages into an artifact; the agent job unpacks. `apm.lock` pins every package to a commit SHA — review lock diffs in PRs.

Token fallback: `GH_AW_PLUGINS_TOKEN` → `GH_AW_GITHUB_TOKEN` → `GITHUB_TOKEN`.

---

## Dependabot Integration

`gh aw compile --dependabot` scans workflows for runtime tools (`npx`, `pip install`, `go install`) and emits manifests in `.github/workflows/`: `package.json` + `package-lock.json` (needs npm), `requirements.txt`, `go.mod`. Also updates `.github/dependabot.yml` (existing entries preserved).

Must compile ALL workflows — cannot target a single file or `--dir`.

**NEVER merge Dependabot PRs that only touch generated manifests** — they get overwritten. Instead: edit the version in the source `.md` workflow, rerun `gh aw compile --dependabot`, commit. Dependabot auto-closes its PR.

**Add `github/gh-aw-actions` to the `ignore:` list** in `dependabot.yml` — those pins are managed by `gh aw compile` / `gh aw update-actions`, not Dependabot.

---

## gh-aw as MCP Server

`gh aw mcp-server` exposes CLI commands to any MCP host (Copilot Chat, VS Code, Claude Code). `gh aw init` wires it into `.vscode/mcp.json` and `.github/workflows/copilot-setup-steps.yml` automatically (`--no-mcp` to skip).

Tools exposed: `status`, `compile` (with zizmor/poutine/actionlint), `logs`, `audit`, `checks`, `mcp-inspect`, `add`, `update`, `fix`.

`--validate-actor` requires write/maintain/admin on the repo before log/audit tools respond (reads `GITHUB_ACTOR` + `GITHUB_REPOSITORY`, 1h cache).

Self-management from within a workflow:

```yaml
permissions:
  actions: read
tools:
  agentic-workflows:
```

---

## Versioning

Two layers: the `gh aw` CLI extension AND the compiled `.lock.yml` (embeds `GH_AW_INFO_AWF_VERSION`). At runtime, activation fetches `.github/aw/releases.json` and enforces `blockedVersions` / `minimumVersion` (fail) or `minRecommendedVersion` (warn).

Pin CLI in CI:

```yaml
- uses: github/gh-aw/actions/setup-cli@main
  with:
    version: v0.64.5
```

### `gh aw upgrade` vs `gh aw update`

- **`upgrade`** — tooling: self-update extension, regenerate dispatcher, apply codemods, refresh action pins, recompile. Run after installing a new gh-aw.
- **`update`** — content: pull workflow markdown from the `source:` field upstream (3-way merge; `--no-merge` to overwrite).

Both support `--create-pull-request`.

---

## Compilation Checklist

After modifying any `.github/workflows/*.md`:

- [ ] Run `gh aw compile` — check for errors
- [ ] Run `gh aw compile --actionlint --zizmor --poutine` — full security scan
- [ ] Stage the `.lock.yml` alongside the `.md`
- [ ] Stage `.github/aw/actions-lock.json` if changed (**required for restricted-token environments**)
- [ ] Add `github/gh-aw-actions` to `ignore:` in `.github/dependabot.yml`
- [ ] Verify `network.allowed` uses ecosystem identifiers (not individual domains)
- [ ] Verify `permissions:` are read-only — writes go through `safe-outputs`
- [ ] Verify `tools.github.min-integrity:` is set (`approved` for public repos, explicit for private)
- [ ] Verify `threat-detection:` prompt matches the workflow's actual threat model
- [ ] For PR triggers: verify `forks:` allowlist is explicit (default is deny)
- [ ] For new workflows: start with `safe-outputs.staged: true`, remove once stable
- [ ] If workflow uses runtime tools (`npx`/`pip`/`go install`), run `gh aw compile --dependabot`
- [ ] Use `gh aw validate --strict` in CI to gate PRs

---

## Known Gotchas

- **`lockdown:` is deprecated.** Migrate to `tools.github.min-integrity`. Run `gh aw fix <workflow> --write` to auto-migrate.
- **`dependencies:` is deprecated.** Migrate to APM via `shared/apm.md` import.
- **`plugins:` was removed.** Migrated to `dependencies:` (which is itself now deprecated → APM).
- **Top-level `roles:` / `bots:` are deprecated.** Migrate to `on.roles:` / `on.bots:`.
- **`needs.activation.outputs.*` is deprecated.** Use `steps.sanitized.outputs.*`.
- **macOS / Windows runners NOT supported** — sandbox requires Linux containers.
- **Cross-org `workflow_call`** fails with `ERR_SYSTEM: Runtime import file not found` → set `inlined-imports: true` on the callee.
- **Repository rulesets as required checks** → same fix, `inlined-imports: true`.
- **`CLAUDE_CODE_OAUTH_TOKEN` not supported** — Claude engine requires `ANTHROPIC_API_KEY`.
- **`create-discussion` failing** — needs `discussions: write` + discussions enabled on repo; use lowercase category slugs. `fallback-to-issue: true` is default.
- **Org blocks PR creation** — `fallback-as-issue: true` (default) creates an issue with a branch link instead.
- **Dependabot PRs against `github/gh-aw-actions` — DO NOT MERGE.** Ignore in `dependabot.yml`.
- **`push-to-pull-request-branch` cannot push to fork PRs** — GitHub security restriction.
- **Agent PRs don't trigger CI** by default — set `GH_AW_CI_TRIGGER_TOKEN` (see Triggering CI section).
- **GitHub App tokens rejected by `assign-to-agent`** — Copilot assignment API requires a PAT.
- **`runs-on` only applies to the agent job.** Framework jobs use `runs-on-slim` (defaults to `ubuntu-slim`).
- **Services containers** expose ports on the runner host, not the agent namespace. Connect via `host.docker.internal:<port>`.

---

## Key Terms

- **Activation job** — builds the prompt and sanitizes context. Outputs referenced as `steps.sanitized.outputs.*` in the prompt body, `needs.activation.outputs.*` from downstream jobs.
- **Lock file (`.lock.yml`)** — compiled workflow, SHA-pinned, committed. Regenerate on ANY frontmatter change; body reloads at runtime.
- **Safe outputs** — structured write operations executed in a separate job with scoped permissions. Agent job stays read-only.
- **MCP gateway** — filters GitHub content by integrity before the agent sees it. Always on.
- **AWF (Agent Workflow Firewall)** — egress-control container enforcing `network.allowed`. Why macOS/Windows are unsupported.
- **DIFC (Data Integrity Flow Control)** — the proxy that enforces integrity at the network boundary when `min-integrity` is set.
- **`actions-lock.json`** — cached `action@version → SHA` map under `.github/aw/`. Commit; refresh with `gh aw update-actions`.
- **APM** — Agent Package Manager. Replaces the deprecated `dependencies:` field.

---

## .gitattributes

Add to repo root so lock files auto-resolve on merge:

```
.github/workflows/*.lock.yml linguist-generated=true merge=ours
```

---

## Resources

- **Source docs (authoritative)**: https://github.com/github/gh-aw/tree/main/docs/src/content/docs/
- **Rendered site**: https://github.github.com/gh-aw/ (may lag source)
- **Local references**: See [references/](references/) for existing workflow and agent examples in this repo, plus a `gh api` cheat sheet
- **Dispatcher agent (Copilot Chat / VS Code Agent Mode)**: `/agent agentic-workflows create|update|upgrade|import|debug ...`
