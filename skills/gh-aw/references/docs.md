# GitHub Agentic Workflows Documentation

## Local Examples

Working workflow and agent files in this repo:

- `.github/workflows/issue-triage.md` - Workflow frontmatter + context dispatcher (LabelOps pattern)
- `.github/agents/issue-triage.md` - Full triage agent persona with output format
- `.github/workflows/issue-triage.lock.yml` - Compiled lock file (auto-generated)
- `.github/aw/actions-lock.json` - Action SHA pinning
- `.gitattributes` - Lock file merge strategy

## Official Documentation — ALWAYS READ FROM THE SOURCE

**Canonical source:** https://github.com/github/gh-aw/tree/main/docs/src/content/docs/

Read the raw markdown files directly from the repo — not the rendered site. The rendered pages at `github.github.com/gh-aw/` can lag, strip structure, or summarize away exact field names. The `.md` and `.mdx` files in the repo are the authoritative source.

Use `gh api` to list the reference directory and pull individual files:

```bash
# List every reference page
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference' --jq '.[] | .name'

# Read a specific page (raw content)
gh api 'repos/github/gh-aw/contents/docs/src/content/docs/reference/engines.md' --jq '.content' | base64 -d
```

Top-level doc directories in the repo:

- `docs/src/content/docs/reference/` — engine, safe-outputs, triggers, tools, imports, network, threat-detection, compilation-process, lockdown-mode, concurrency, permissions, sandbox, cache-memory, cost-management, rate-limiting-controls, and ~40 more
- `docs/src/content/docs/guides/` — MCP servers, patterns
- `docs/src/content/docs/introduction/` — architecture, how-they-work, overview
- `docs/src/content/docs/setup/` — quick-start, creating-workflows

The rendered site (`github.github.com/gh-aw/`) remains useful for quick human browsing but is NOT the source of truth.
