# Changelog fragments

Each PR adds one small file here instead of editing `CHANGELOG.md` directly, so concurrent PRs never conflict.

- Filename: `<slug>.<type>.md`, e.g. `my-new-check.added.md` (slug is free-form: letters, digits, `.`, `_`, `-`)
- `<type>` is one of: `added`, `changed`, `deprecated`, `removed`, `fixed`, `security`
- Content: one line with the changelog entry text, without the PR link and without a trailing period (the PR link is attached automatically at release time)
- A PR adds as many fragment files as entries it needs, freely mixing types (one file per entry); same-type entries just use different slugs

Fragments are compiled into `CHANGELOG.md` when a release is prepared. Full conventions: `skills/prowler-changelog/SKILL.md`.
