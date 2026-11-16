---
name: prowler-ui-browser-review
description: >
  Browser sign-off for user-visible Prowler UI changes: when to drive a browser and when to hand over a URL, running the app, viewports, what to check, and the evidence to post on the PR.
  Trigger: When a UI change affects layout, styling, navigation, responsive behavior, loading/empty/error states or a multi-step flow, and before calling user-visible UI work done.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.4"
  scope: [root, ui]
  auto_invoke: "Verifying a user-visible UI change in the browser"
allowed-tools: Read, Glob, Grep, Bash
---

## When to Drive a Browser

No unit test loads a real page, so a rendering change is only verified once someone looks at it. Drive a browser when the outcome is uncertain:

- Flows that carry state: wizards, modals opened from menus, the side panel, multi-step forms.
- Layout that can reflow: tables, mobile widths, the side panel pushing `<main>` (breakpoints are container queries there).
- Server/client boundary changes, such as filter props passed from a Server Component. jsdom tests skip that hop; only the real page throws.
- Data that loads after first paint and could push content down.
- Final sign-off of a substantial user-visible change.

## When to Hand Over a URL Instead

For a small visual change you are confident about (a token, a label, an icon), say what changed, give the exact URL, and name what you did not check. Do this only while a developer is there to look. If nobody is around and the change is user-visible, check it yourself.

## Run the App

```bash
# From the repo root: local API (Django, Postgres, Valkey, worker) on :8080
docker compose -f docker-compose-dev.yml up -d api-dev worker-dev

# UI on :3000. First run only: create ui/.env.local (an existing file is left alone)
cd ui
[ -f .env.local ] || cat > .env.local <<EOF
UI_API_BASE_URL=http://localhost:8080/api/v1
AUTH_URL=http://localhost:3000
AUTH_SECRET=$(openssl rand -base64 32)
AUTH_TRUST_HOST=true
EOF
UI_API_BASE_URL=http://localhost:8080/api/v1 pnpm run dev
```

- `lib/env.ts` stops the boot when `UI_API_BASE_URL`, `AUTH_URL` or `AUTH_SECRET` is missing. Next does not read the root `.env` from `ui/`; that file lists the other UI variables.
- To point an existing `.env.local` at another API for one run, set the variable on the process: `UI_API_BASE_URL=<url> pnpm run dev`. A value already in the environment wins over `.env.local`.
- Reuse a dev server that is already running; do not start a second one on another port.
- Authenticated routes need a signed-in user. Never type a developer's real password: ask them to sign in, or use a test account created for the local stack.
- Cloud-only screens (Realtime, Lighthouse v2, upgrade prompts) render only with `UI_CLOUD_ENABLED=true` and an API that serves them.

## Review Loop

1. Open the changed route and exercise the main path the change affects.
2. Check the three widths the PR template asks for: mobile (375×812), tablet (768×1024) and desktop (1440×900).
3. Open the side panel on the changed page: `<main>` shrinks and its `sm:`…`2xl:` variants follow its width, not the viewport.
4. Check loading, empty and error states. Throttle the network or point at an empty tenant if needed.
5. Check for layout shift: read element positions (`getBoundingClientRect`) at first paint and after data loads. Screenshots alone miss it.
6. Use the keyboard: tab order, visible focus, `Esc` closes overlays and returns focus.
7. Read the browser console for hydration errors and "Functions cannot be passed directly to Client Components".

## Tools

- Use the browser automation your agent has: the Claude desktop Browser pane, the `playwright` MCP server from the repo `.mcp.json`, or your editor's browser.
- `next-devtools` (also in `.mcp.json`) reads build errors, runtime errors and routes from the running `next dev`.
- Never reuse a developer's personal browser session unless they ask for it.

## Evidence

Report the flow you reviewed, whether it worked, any regressions, and what you did not check. Post screenshots for the three widths on the PR, not only in chat. For flows, a short recording beats a list of screenshots.

## Commands

```bash
cd ui
pnpm run test:integration   # browser-mode Vitest (real layout, React Compiler on)
pnpm run test:e2e           # Playwright E2E against a running stack
```

## Resources

- `ui/AGENTS.md`: verification by change type
- `prowler-test-ui`: write a Playwright spec when the flow needs a permanent guard
