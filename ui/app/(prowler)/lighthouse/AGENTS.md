# Lighthouse AI

Read this before changing Lighthouse chat, its stream, or anything under this folder. General UI rules live in `ui/AGENTS.md`.

## Two Implementations

`page.tsx` picks the version: `isCloud()` renders v2, self-hosted renders v1.

|                 | v1 (self-hosted)                                         | v2 (Prowler Cloud)                                                                   |
| --------------- | -------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| UI              | `components/lighthouse-v1/`                              | `_components/` (chat, side panel, AI Elements)                                       |
| Logic           | `lib/lighthouse-v1/` (LangGraph workflow, MCP client)    | Django sessions; client state in `_lib/chat-store.ts` and `_lib/panel-chat-store.ts` |
| Transport       | AI SDK `useChat` → `app/api/lighthouse/analyst/route.ts` | `EventSource` on `app/api/lighthouse/v2/sessions/[sessionId]/event-stream/route.ts`  |
| Actions / types | `actions/lighthouse-v1/`, `types/lighthouse-v1/`         | `_actions/`, `_types/`                                                               |

Shared by both: `lib/lighthouse/` (page context, skills), `components/lighthouse/`, `store/lighthouse-context/`, `lib/lighthouse-routes.ts`. New v2 code stays in this folder; v1 stays in its legacy folders.

## v2 Stream Contract

The backend publishes chat events over SSE with no replay buffer and sends no byte until the first event. Each rule below fixed a real bug:

- **Subscribe before you POST.** Open the `EventSource` (`startStream`) before `sendLighthouseV2Message`, or the first events are lost. Do not wait for the `open` event before posting: nothing arrives until the post starts the run, so that deadlocks.
- **Never remount the chat mid-run.** The page is `force-dynamic` and keyed by session, so `router.push` or `revalidatePath("/lighthouse")` on session create kills the stream. Set `?session=` with `window.history.replaceState` (only the full-page chat may touch the URL; the side panel never does).
- **Stream through the same-origin route.** The browser cannot open an `EventSource` against the API host, and the token must stay on the server. Build the URL with `buildLighthouseV2StreamUrl` (`_lib/stream-url.ts`).
- **Reconcile from the server.** On `message.end` or `error`, `refreshMessages` reloads the persisted messages and replaces the list, which recovers any delta that arrived before the subscription. Swap messages and reset the stream state in one store update so nothing flickers.
- **Finished messages render static.** `message-markdown.tsx` uses `Streamdown` in `static` mode once a message is done; streaming mode mounts empty and leaves a blank frame.

## Progress UI

Show what the agent is doing from real stream events: the running tool, or "Thinking…" between tools, plus the tool-call timeline. Never show step counts or determinate bars based on the model reporting its own progress; runs are not deterministic.

## Tests

- `_lib/` holds pure logic with unit tests next to each file (`event-reducer`, `messages`, `tool-calls`, stores).
- Stream ordering and remount behavior need a browser test or a real run; jsdom cannot show a lost event.

```bash
cd ui
pnpm exec vitest run --project unit "app/(prowler)/lighthouse"
pnpm exec vitest run "app/api/lighthouse"
```
