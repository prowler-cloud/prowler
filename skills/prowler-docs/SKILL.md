---
name: prowler-docs
description: >
  Prowler documentation style guide and writing standards.
  Trigger: When writing documentation for Prowler features, tutorials, or guides.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, docs]
  auto_invoke: "Writing documentation"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## When to Use

Use this skill when writing or reviewing Prowler documentation for:
- Feature documentation
- API/SDK references
- Tutorials and guides
- Release notes
- PR documentation reviews

## Source of Truth

**CRITICAL**: Read `docs/AGENTS.md` for the complete documentation style guide. This file contains all brand voice guidelines, formatting standards, SEO rules, and writing conventions.

```bash
# Read the full documentation style guide
cat docs/AGENTS.md
```

The `docs/AGENTS.md` file is the authoritative source for:
- Brand voice and tone
- Unbiased communication guidelines
- Naming conventions (Prowler features as proper nouns)
- Verbal vs nominal constructions
- Title-case capitalization rules
- Hyphenation patterns
- Bullet point formatting
- Quotation mark usage
- Interaction verbs (click, tap, etc.)
- SEO optimization (sentence structure, headers)
- Section titles and headers
- Version badge usage
- Warnings and danger calls

## Quick Reference (Summary)

These are highlights — always consult `docs/AGENTS.md` for complete guidance:

### Brand Voice
- Avoid gendered pronouns (use "you/your" or "they/them")
- Use inclusive alternatives: businessman → businessperson
- Avoid militaristic language: fight → address, kill chain → cyberattack chain

### Formatting
- **Title Case** for all headers: "How to Configure Security Scanning"
- **Verbal constructions** preferred: "The report was created" not "The creation of the report"
- **Keywords first** in sentences for SEO: "To create a role, open terminal..."

### Prowler Features (Proper Nouns)
Reference without articles: Prowler App, Prowler CLI, Prowler SDK, Prowler Cloud, Prowler Studio

### MDX Components
```mdx
import { VersionBadge } from "/snippets/version-badge.mdx"

## New Feature

<VersionBadge version="4.5.0" />
```

## Documentation Structure

```
docs/
├── AGENTS.md              # Documentation style guide (SOURCE OF TRUTH)
├── getting-started/
├── tutorials/
├── providers/
│   ├── aws/
│   ├── azure/
│   └── gcp/
├── api/
├── sdk/
├── compliance/
└── developer-guide/
```

## Review Checklist

When reviewing documentation PRs, verify against `docs/AGENTS.md`:
- [ ] Title case capitalization on headers
- [ ] No gendered pronouns
- [ ] Verbal constructions (not nominal)
- [ ] Keywords at beginning of sentences
- [ ] Prowler features referenced as proper nouns (no articles)
- [ ] Acronyms defined on first use
- [ ] Version badge for new features
- [ ] Bullet points for lists (3+ items)

## Resources

- **Full Style Guide**: `docs/AGENTS.md`
- **Developer Guide**: `docs/developer-guide/documentation.mdx`
