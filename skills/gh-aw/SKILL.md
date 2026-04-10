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

---

## Upstream Docs (source of truth)

**Always read gh-aw docs from the repo source, not the rendered site.** The rendered pages at `github.github.com/gh-aw/` can lag or summarize away field names. The markdown source in the repo is authoritative.

```bash
# List every reference page
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference' --jq '.[] | .name'

# Read a specific page (raw markdown)
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference/<filename>' --jq '.content' | base64 -d
```

When you need details on any gh-aw feature, read the upstream doc FIRST. Only use this skill for Prowler-specific patterns and the reference index below.

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
    ├── actions-lock.json      # Action SHA pinning — COMMIT THIS
    └── imports/               # Compile-time cache of cross-repo imports
```

`.github/workflows/shared/` is the convention for reusable components imported by multiple workflows. See [references/docs.md](references/docs.md) for local examples.

---

## Prowler-Specific Patterns

### Agent personas vs. skill-sourced workflows

For complex agents with multi-step reasoning (like `issue-triage`), use the two-file architecture: workflow `.md` imports agent persona from `.github/agents/`. For thin reviewer workflows whose job is "apply skill X to artifact Y" (like `pr-changelog-review`), inline the prompt in the workflow and have it read the skill file at runtime. Do not create an agent persona that restates a skill — the skill file is the source of truth and updating two files is drift waiting to happen.

### Sanitized context

Use `${{ steps.sanitized.outputs.text }}` — NEVER raw `github.event.issue.body`. The older form `${{ needs.activation.outputs.text }}` is DEPRECATED (compiler rewrites it).

### Markdown body is hot-editable

Only frontmatter drives compilation. Prompt edits in the body can go straight to `main` without `gh aw compile`. Frontmatter edits require recompile — the frontmatter-hash mismatch auto-files an issue at runtime.

### Read-only permissions + safe outputs

Agent job is read-only. Writes go through `safe-outputs:` (executed in a separate job with scoped permissions). The agent never sees a write token. NEVER put `${{ secrets.* }}` in top-level `env:` — strict mode errors, non-strict warns, because workflow env leaks to the agent container.

### Strict mode on public repos

`strict: true` (default) enforces: no writes, explicit network, ecosystem identifiers, SHA-pinned actions. `strict: false` **FAILS AT RUNTIME on public repositories** — the error tells the operator to recompile in strict mode. Prowler is a public repo: always use `strict: true` or `strict: false` only when MCP servers require custom domains.

### The `noop` trap

If the agent finishes WITHOUT calling any safe-output tool, the workflow **fails silently with no output** — documented as the #1 runtime failure mode. Always instruct the agent to call `noop` when its analysis concludes no action is needed.

### Prowler network baseline

```yaml
network:
  allowed:
    - defaults
    - python
    - github
```

Add `"mcp.prowler.com"` and `"mcp.context7.com"` only for workflows using those MCP servers. When adding custom domains, use `strict: false` (strict rejects non-ecosystem domains).

### Prowler MCP server config

```yaml
mcp-servers:
  prowler:
    url: "https://mcp.prowler.com/mcp"
    allowed:
      - prowler_hub_list_providers
      - prowler_hub_get_provider_services
      - prowler_hub_list_checks
      - prowler_hub_semantic_search_checks
      - prowler_hub_get_check_details
      - prowler_hub_get_check_code
      - prowler_hub_get_check_fixer
      - prowler_hub_list_compliances
      - prowler_hub_semantic_search_compliances
      - prowler_hub_get_compliance_details
      - prowler_docs_search
      - prowler_docs_get_document

  context7:
    url: "https://mcp.context7.com/mcp"
    allowed:
      - resolve-library-id
      - query-docs
```

Always use `allowed:` to restrict tools (least-privilege). See `issue-triage.md` for a working example.

### Harden-Runner (known limitation)

`steps:` in frontmatter injects pre-steps into the **agent job only**. The 5-6 framework jobs (`pre_activation`, `activation`, `detection`, `safe_outputs`, `conclusion`) are NOT covered. As of v0.67.1 there is NO global hardening mechanism.

```yaml
steps:
  - name: Harden Runner
    uses: step-security/harden-runner@fa2e9d605c4eeb9fcad4c99c224cee0c6c7f3594 # v2.16.0
    with:
      egress-policy: audit
```

**Do NOT patch the generated `.lock.yml` by hand.** Every `gh aw compile` wipes manual edits. Partial coverage (agent job only) is still better than none.

### Integrity filtering (replaces deprecated `lockdown:`)

`lockdown:` is DEPRECATED. Migrate to `tools.github.min-integrity`:

```yaml
tools:
  github:
    min-integrity: approved          # public repos default to this even if unset
    blocked-users: ["spam-bot"]
```

Migration: `lockdown: true` becomes `min-integrity: approved`; `lockdown: false` becomes `min-integrity: none`. Run `gh aw fix <workflow> --write` to auto-migrate.

### Triggering CI on agent-created PRs

PRs created with the default `GITHUB_TOKEN` DO NOT trigger CI. Set the magic secret:

```bash
gh aw secrets set GH_AW_CI_TRIGGER_TOKEN --value "<PAT with contents:write>"
```

gh-aw pushes an extra empty commit with this token, triggering `push`/`pull_request` events. Applies to `create-pull-request` AND `push-to-pull-request-branch`.

---

## Compilation Checklist

After modifying any `.github/workflows/*.md`:

- [ ] Run `gh aw compile` — check for errors
- [ ] Run `gh aw compile --actionlint --zizmor --poutine` — full security scan
- [ ] Stage the `.lock.yml` alongside the `.md`
- [ ] Stage `.github/aw/actions-lock.json` if changed (required for restricted-token envs)
- [ ] Add `github/gh-aw-actions` to `ignore:` in `.github/dependabot.yml`
- [ ] Verify `network.allowed` uses ecosystem identifiers (not individual domains)
- [ ] Verify `permissions:` are read-only — writes go through `safe-outputs`
- [ ] Verify `tools.github.min-integrity:` is set (NOT the deprecated `lockdown:`)
- [ ] Verify `threat-detection:` prompt matches the workflow's actual threat model
- [ ] For PR triggers: verify `forks:` allowlist is explicit (default is deny)
- [ ] For new workflows: start with `safe-outputs.staged: true`, remove once stable
- [ ] Use `gh aw validate --strict` in CI to gate PRs

---

## Commands Quick Reference

```bash
# Compile
gh aw compile                                 # all workflows
gh aw compile <workflow>
gh aw compile --strict
gh aw compile --no-emit                       # validate without writing .lock.yml
gh aw compile --actionlint --zizmor --poutine # full security scan
gh aw compile --purge                         # remove orphaned .lock.yml files
gh aw compile --dependabot                    # generate dep manifests

# Validate (compile + all linters, no output)
gh aw validate --strict --json

# Lifecycle
gh aw upgrade                                 # tooling: self-update + codemods + recompile
gh aw update                                  # content: pull workflow .md from source repo
gh aw update-actions                          # refresh actions-lock.json SHA pins

# Runtime
gh aw status
gh aw run <workflow>
gh aw logs [workflow] --format markdown --count 10

# Audit & forensics
gh aw audit <run-id>
gh aw audit <run-id> --parse                  # emit log.md + firewall.md
gh aw audit diff <base> <comp>                # behavioral diff

# Secrets
gh aw secrets set NAME --value "..."
gh aw secrets bootstrap

# Fix deprecated fields
gh aw fix <workflow> --write
```

---

## Known Gotchas

- **`lockdown:` is deprecated.** Use `tools.github.min-integrity`. Run `gh aw fix --write`.
- **`dependencies:` is deprecated.** Use APM via `shared/apm.md` import.
- **`needs.activation.outputs.*` is deprecated.** Use `steps.sanitized.outputs.*`.
- **Top-level `roles:` / `bots:` deprecated.** Use `on.roles:` / `on.bots:`.
- **macOS / Windows runners NOT supported** — sandbox requires Linux containers.
- **Cross-org `workflow_call`** fails with `ERR_SYSTEM: Runtime import file not found` — set `inlined-imports: true`.
- **`CLAUDE_CODE_OAUTH_TOKEN` not supported** — Claude requires `ANTHROPIC_API_KEY`.
- **Agent PRs don't trigger CI** by default — set `GH_AW_CI_TRIGGER_TOKEN`.
- **GitHub App tokens rejected by `assign-to-agent`** — Copilot API requires a PAT.
- **`runs-on` only affects the agent job.** Framework jobs use `runs-on-slim` (default `ubuntu-slim`).
- **`push-to-pull-request-branch` cannot push to fork PRs** — GitHub security restriction.
- **Services containers**: connect via `host.docker.internal:<port>`, not `localhost`.
- **Dependabot PRs against `github/gh-aw-actions`** — DO NOT MERGE. Add to `ignore:` in `dependabot.yml`.
- **`strict: false` fails at runtime on public repos** — recompile with `strict: true`.

---

## .gitattributes

```
.github/workflows/*.lock.yml linguist-generated=true merge=ours
```

---

## Reference Index

For detailed coverage of any topic, read the upstream doc directly:

```bash
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference/<file>' --jq '.content' | base64 -d
```

### Core configuration

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| All frontmatter fields | `frontmatter.md`, `frontmatter-full.md` | Any frontmatter question |
| Workflow structure and lock file metadata | `workflow-structure.md` | Understanding compiled output |
| Engines (4 engines, extended block, timeouts, token weights) | `engines.md` | Engine config, model selection, version pinning |
| Permissions reference | `permissions.md` | Setting `permissions:`, `id-token:` |
| Environment variables (13 scopes, system vars) | `environment-variables.md` | Env config, debugging |

### Triggers and scheduling

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| All trigger types, pre-activation, skip-if, forks, manual-approval | `triggers.md` | Workflow trigger design |
| Slash and label commands (ChatOps) | `command-triggers.md` | Bot-command workflows |
| Fuzzy and cron schedules, timezones | `schedule-syntax.md` | Scheduled workflows |

### Tools and capabilities

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Tools reference (bash, github, web, edit, etc.) | `tools.md` | Configuring `tools:` |
| GitHub toolsets (default, code_security, etc.) | `github-tools.md` | GitHub read config |
| Checkout field (fetch-depth, cross-repo, sparse) | `checkout.md` | Repo checkout config |
| Playwright (browser automation) | `playwright.md` | UI testing workflows |
| MCP Gateway (infrastructure) | `mcp-gateway.md` | Debugging MCP issues |
| MCP Scripts (inline custom tools) | `mcp-scripts.md` | Custom tool authoring |

### Imports and network

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Import resolution (3 modes, parameterized, runtime, merge) | `imports.md` | Composing shared workflows |
| Network allowlist (ecosystem IDs, firewall, SSL bump) | `network.md` | Egress configuration |
| Cross-repository operations | `cross-repository.md` | Multi-repo workflows |

### Security

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Integrity filtering (replaces lockdown) | `integrity.md` | Content trust filtering |
| Lockdown mode (DEPRECATED) | `lockdown-mode.md` | Migration reference only |
| Sandbox architecture (AWF) | `sandbox.md` | Understanding agent isolation |
| Fork support (workflow-in-fork + inbound PRs) | `fork-support.md` | Fork security |
| Threat detection (prompt, steps, artifacts) | `threat-detection.md` | Hardening safe outputs |

### Safe outputs

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| All safe output types (40+), shared options, noop | `safe-outputs.md` | Configuring writes |
| PR-specific outputs (review comments, protected files) | `safe-outputs-pull-requests.md` | PR code-write workflows |
| Custom safe outputs (scripts, actions, jobs) | `custom-safe-outputs.md` | Third-party integrations |
| Footers (variables, per-type, hidden markers) | `footers.md` | Footer customization |
| Assign to Copilot coding agent | `assign-to-copilot.mdx` | Agent handoff |

### Operations

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Concurrency (dual-level, fan-out) | `concurrency.md` | Execution serialization |
| Rate limiting (max, window, ignored-roles) | `rate-limiting-controls.md` | Abuse prevention |
| Cost management (observability, spend reduction) | `cost-management.md` | Budget control |
| Token accounting (effective tokens formula) | `tokens.md`, `effective-tokens-specification.md` | Cost analysis |
| Cache memory (cross-run file storage) | `cache-memory.md` | Session state |
| Repo memory (git-backed persistent state) | `repo-memory.md` | Long-term state |

### Build and lifecycle

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Compilation pipeline (5 phases) | `compilation-process.md` | Understanding compile |
| Staged mode (safe output preview) | `staged-mode.md` | Testing new workflows |
| Dependencies (APM packages) | `dependencies.md` | Package management |
| Dependabot integration | `dependabot.md` | Automated dep updates |
| Versioning and upgrades | `releases.md` | CLI version management |
| Audit and forensics | `audit.md` | Run investigation |

### Authoring

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Templating (expression allowlist, conditionals) | `templating.md` | Writing prompt bodies |
| Markdown body scanner (security) | `markdown.md` | Understanding rejections |
| Custom agent files (.github/agents/) | `custom-agent-for-aw.mdx` | Agent persona authoring |
| gh-aw as MCP server | `gh-aw-as-mcp-server.md` | Dev tooling integration |

### Authentication

| Topic | Upstream doc | When to read |
|-------|-------------|--------------|
| Engine secrets and GitHub auth | `auth.mdx` | Setting up secrets |
| Projects authentication | `auth-projects.mdx` | Projects integration |

---

## Resources

- **Upstream docs (authoritative)**: `github.com/github/gh-aw/tree/main/docs/src/content/docs/`
- **Dispatcher agent**: `/agent agentic-workflows create|update|upgrade|import|debug`

### Local examples in this repo

- `.github/workflows/issue-triage.md` — LabelOps workflow with MCP servers (frontmatter + context dispatcher)
- `.github/agents/issue-triage.md` — full triage agent persona with output format
- `.github/workflows/issue-triage.lock.yml` — compiled lock file (auto-generated)
- `.github/workflows/pr-changelog-review.md` — inline-prompt workflow (no separate agent file, reads skill at runtime)
- `.github/workflows/pr-changelog-review.lock.yml` — compiled lock file (auto-generated)
- `.github/aw/actions-lock.json` — action SHA pinning
- `.gitattributes` — lock file merge strategy
