# UI Documentation

## Local Documentation

- `docs/developer-guide/lighthouse-architecture.mdx` - Lighthouse AI (v1) architecture: workflow, MCP client, meta-tools, stream handler.
  Note: the doc still says `ui/lib/lighthouse/`; the v1 code lives in `ui/lib/lighthouse-v1/` (and `ui/components/lighthouse-v1/`).
- `docs/developer-guide/end2end-testing.mdx` - Playwright E2E setup, auth setup projects, `E2E_*` env vars.
- `docs/developer-guide/server-sent-events.mdx` - API-side SSE infrastructure (`api.sse`); the UI consumes it through Next.js proxy routes such as `app/api/lighthouse/v2/sessions/[sessionId]/event-stream/route.ts`.
- `ui/AGENTS.md` - UI rules (React, types, styling, scope rule).
- `ui/components/shadcn/README.md` - shadcn component layout and barrel exports.
