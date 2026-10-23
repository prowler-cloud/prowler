# CodeRabbit → Slack → local review agent

When CodeRabbit submits a review with actionable comments on the PR's current head, the
`coderabbit-notify` workflow sends the PR author one Slack direct message. Its button opens the
launcher page, which starts Claude Code, Claude Desktop or Codex Desktop with
`/address-review <pr> <sha>` prefilled. The `address-review` skill in `skills/` does the rest.

Nothing here calls a model. The agent runs on the author's machine and account after they press send.

## Files

| Path | Purpose |
|------|---------|
| `../workflows/coderabbit-notify.yml` | Trigger on `pull_request_review`, decide, dedup, send |
| `notify.mjs` | `decide` (reads the event, checks the head, writes the message) and `send` (Slack) |
| `lib.mjs` | Pure helpers: review parsing, decision, Slack message, launcher URL |
| `lib.test.mjs` + `fixtures/` | Tests against real CodeRabbit review objects recorded from PR 13093 |
| `slack-users.json` | GitHub login → Slack member id. Unmapped authors get no message |
| `launcher/index.html` | Static page that builds the three deep links |

## Setup

1. **Slack app.** Create a bot with the `chat:write` and `im:write` scopes, install it in the
   workspace and store its token as the repository secret `CODERABBIT_SLACK_BOT_TOKEN`.
2. **Launcher.** Host `launcher/index.html` on any HTTPS origin (GitHub Pages or an internal host)
   and store its URL as the repository variable `CODERABBIT_LAUNCHER_URL`. Without it, the message
   still goes out with the command to run and only the pull request button.
3. **Authors.** Add each author to `slack-users.json`. Slack member ids start with `U` and are
   shown under "Copy member ID" in a Slack profile.

## How a review is filtered

A message is sent only when all of these hold:

- the review comes from `coderabbitai[bot]` and its body contains `Actionable comments posted: N` with N > 0;
- the review's `commit_id` equals the PR head read from the API at run time (older reviews are superseded);
- the PR is still open at run time and its author is in `slack-users.json`;
- the review's `publication` id (an HTML marker CodeRabbit leaves in the body) has not been seen.
  Seen ids are stored in the Actions cache under `coderabbit-notify-<id>`, so a redelivered event
  does not send a second message.

## Local checks

```bash
node --test .github/coderabbit-notify/lib.test.mjs
```

To try `decide` against a recorded event without Slack (it reads the live PR head and state, so it
needs a GitHub token):

```bash
GH_TOKEN=$(gh auth token) GITHUB_EVENT_PATH=/path/to/event.json node .github/coderabbit-notify/notify.mjs decide
```

## Still to verify in the pilot

- Secrets on `pull_request_review` events for fork PRs. Fork authors are unmapped by default, so
  nothing is sent either way, but the `decide` step should not fail.
- Codex behaviour when `originUrl` matches no workspace; the launcher passes `path` as a hint.
- Slack clients that refuse `claude-cli://`, `claude://` or `codex://` from the launcher page.
  The page shows a terminal command as the fallback.
