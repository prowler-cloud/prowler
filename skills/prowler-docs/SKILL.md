---
name: prowler-docs
description: >
  Prowler documentation style guide, product naming and Mintlify conventions for docs/.
  Trigger: When writing or editing Prowler documentation (docs/**/*.mdx, docs/docs.json) for features, tutorials, guides, or the developer guide.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root]
  auto_invoke: "Writing documentation"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Source of Truth

`docs/AGENTS.md` is the full style guide (brand voice, capitalization, hyphenation, bullets, quotation marks, headers, Version Badge, AppliesTo, cloud marker, warnings). Read the relevant section before writing; this skill is the short version plus the Mintlify mechanics.

## Critical Rules

- **Product names** (proper nouns, no articles): Prowler Cloud, Prowler Private Cloud, Prowler Hub, Prowler Lighthouse AI, Prowler MCP, Prowler CLI, Prowler Local Server, Prowler Local Dashboard, Prowler SDK.
- **NEVER use the former names** "Prowler App" (now Prowler Local Server) or "Prowler Enterprise" (now Prowler Private Cloud) in new writing. Only `getting-started/products/index.mdx` and the site banner document the mapping. Existing URLs such as `user-guide/tutorials/prowler-app-*` keep their paths; the rule applies to prose.
- **Web UI guides are written for Prowler Cloud**: steps link to `https://cloud.prowler.com/sign-in`; state the scope once with `<AppliesTo />`; mention Prowler Local Server inline only where behavior differs.
- **Every new page goes in `docs/docs.json` navigation** (path without `.mdx`). Renamed or moved pages need an entry in `redirects` (`{"source": "/old/path", "destination": "/new/path"}`).
- **Title Case** for headers; American English; define acronyms on first use ("AWS Identity and Access Management (IAM)").
- **Avoid second person** except in imperative instructions; prefer verbal over nominal constructions; no gendered or militaristic language (fight -> address, attacker -> threat actor, kill chain -> cyberattack chain).
- **Goal first** for SEO: "To create a custom role, open a terminal..." not "Open a terminal to create a custom role...".
- UI elements, buttons and exact input go in double quotes: Click "Save". Use Click/Double-click/Right-click (desktop) and Tap/Press and hold/Swipe (touch).

## Page Skeleton

```mdx
---
title: 'Configuring Mute Rules in Prowler Cloud'
---

import { VersionBadge } from "/snippets/version-badge.mdx"
import { AppliesTo } from "/snippets/applies-to.mdx"

<VersionBadge version="5.48.0" />

<AppliesTo />

To mute findings in bulk, ...

## Creating a Mute Rule
```

## MDX Components and Snippets (`docs/snippets/`)

| Snippet / component | Use |
|---------------------|-----|
| `<VersionBadge version="X.Y.Z" />` (`version-badge.mdx`) | Feature, flag, endpoint, check or framework introduced in a version. Own line under the header, no `v` prefix |
| `<AppliesTo />` (`applies-to.mdx`) | Web UI guide valid for several products. Default: Prowler Cloud, Prowler Private Cloud, Prowler Local Server; narrow with `products={["Prowler Cloud", "Prowler Private Cloud"]}`. Below the Version Badge; on provider getting-started pages, under `## Prowler Cloud` |
| `<SubscriptionBanner />` (`subscription-banner.mdx`) | Feature only in Prowler Cloud / Private Cloud. Do not combine with AppliesTo |
| `provider-cards.mdx` | GENERATED: run `python3 docs/scripts/generate_provider_cards.py` (prek hook + CI check) when editing `docs/user-guide/providers/**/getting-started-*.mdx` |
| `<Note>`, `<Warning>`, `<Danger>` (Mintlify) | Low/moderate/high severity. Say the consequence ("Disabling encryption may expose sensitive data"), not just "avoid X". Use notes sparingly |
| `<Steps>`/`<Step title="...">`, `<Tabs>`/`<Tab>` (Mintlify) | Procedures and per-option content |

Subscription-gated pages also get the cloud marker in `docs/style.css` (see "Cloud Marker for Subscription Content" in `docs/AGENTS.md`).

## Documentation Structure

```text
docs/
├── docs.json            # Mintlify config: tabs, groups, pages, redirects
├── AGENTS.md            # Full style guide
├── introduction.mdx
├── getting-started/     # products/, installation/, basic-usage/, comparison/, goto/
├── user-guide/          # tutorials/, providers/<provider>/, cli/, compliance/, cookbooks/, ai-agents/
├── developer-guide/     # checks, services, provider, compliance, outputs, ai-skills, ...
├── security/
├── snippets/            # Reusable MDX components (see table)
├── scripts/             # generate_provider_cards.py
├── images/, img/
├── changelog.mdx, support.mdx, troubleshooting.mdx
└── style.css
```

Navigation tabs in `docs.json`: Getting Started, Guides, Developer Guide, Security, Support, Troubleshooting, Changelog, About Us.

## Commands

```bash
npm install --global mint@4.2.689   # version pinned in docs/README.md
cd docs && mint dev                 # preview at http://localhost:3000
cd docs && mint broken-links        # check internal links
python3 docs/scripts/generate_provider_cards.py   # regenerate provider cards snippet
```

Docs-only PRs (`docs/**`) need no changelog fragment; the PR title type is `docs:`.

## Resources

- **Style guide**: `docs/AGENTS.md`
- **Documentation**: See [references/](references/) for the local contributor guide
