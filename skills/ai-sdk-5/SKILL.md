---
name: ai-sdk-5
description: >
  Vercel AI SDK patterns for the installed major (ui/package.json: `ai` 6.x, `@ai-sdk/react` 3.x).
  The skill name is historical; the APIs below are the v5+/v6 UIMessage API.
  Trigger: When building or changing AI chat/streaming features with the Vercel AI SDK (useChat, DefaultChatTransport, UIMessage parts, UI message streams), including Lighthouse v1 in ui/.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "2.0"
  scope: [root, ui]
  auto_invoke: "Building AI chat features"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Installed Versions (check before coding)

| Package | Version | Notes |
|---------|---------|-------|
| `ai` | 6.x | Core: `DefaultChatTransport`, `UIMessage`, `createUIMessageStreamResponse`, `streamText`, `tool` |
| `@ai-sdk/react` | 3.x | `useChat` hook |
| `@ai-sdk/openai`, `@ai-sdk/langchain` | NOT installed | Prowler drives models through LangChain/LangGraph (`@langchain/*`), not AI SDK providers |

Do not add AI SDK provider packages without checking how Lighthouse is wired first.

## Where AI SDK Is Used in Prowler UI

| File | Role |
|------|------|
| `ui/components/lighthouse-v1/chat.tsx` | `useChat` + `DefaultChatTransport({ api: "/api/lighthouse/analyst" })` |
| `ui/app/api/lighthouse/analyst/route.ts` | LangGraph `streamEvents` -> UI message chunks -> `createUIMessageStreamResponse({ stream })` |
| `ui/lib/lighthouse-v1/analyst-stream.ts` | Chunk builders: `text-start`, `text-delta`, `text-end`, `data-chain-of-thought` |
| `ui/lib/lighthouse-v1/utils.ts` | `UIMessage` -> LangChain message conversion |
| `ui/lib/lighthouse-v1/constants.ts` | `MESSAGE_STATUS` constants compared against `useChat().status` |

Lighthouse v1 (AI SDK) is the OSS path. In Prowler Cloud (`isCloud()`), `app/(prowler)/lighthouse/page.tsx` renders the v2 chat
(`app/(prowler)/lighthouse/_components`, `_lib`), which talks to Django sessions over SSE proxied by
`app/api/lighthouse/v2/sessions/[sessionId]/event-stream/route.ts` and does NOT use the AI SDK.

## Client: useChat

```typescript
"use client";
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { useState } from "react";

export function Chat() {
  const [input, setInput] = useState("");
  const { messages, sendMessage, status, error, stop } = useChat({
    transport: new DefaultChatTransport({
      api: "/api/lighthouse/analyst",
      credentials: "same-origin",
      body: () => ({ model: "gpt-4o" }), // extra JSON merged into the request body
    }),
    onFinish: ({ message }) => {},
    onError: (err) => console.error(err),
  });

  const isBusy = status === "submitted" || status === "streaming";

  return (
    <form
      onSubmit={(e) => {
        e.preventDefault();
        if (!input.trim()) return;
        sendMessage({ text: input });
        setInput("");
      }}
    >
      {messages.map((m) => (
        <div key={m.id}>
          {m.parts.map((part, i) =>
            part.type === "text" ? <p key={i}>{part.text}</p> : null,
          )}
        </div>
      ))}
      <input value={input} onChange={(e) => setInput(e.target.value)} disabled={isBusy} />
      {isBusy && <button type="button" onClick={stop}>Stop</button>}
      {error && <p>{error.message}</p>}
    </form>
  );
}
```

Rules:
- `useChat` comes from `@ai-sdk/react`; the transport from `ai`. There is no `api`, `input`, `handleInputChange`, `handleSubmit` or `isLoading` on `useChat` (v4 API).
- Use `status` (`"submitted" | "streaming" | "ready" | "error"`), not `isLoading`.
- Retry with `regenerate()`, cancel with `stop()`, edit history with `setMessages()`.

## UIMessage Parts

`message.content` does not exist. Render from `message.parts`, switching on `part.type`:

| `part.type` | Shape |
|-------------|-------|
| `"text"` | `{ text }` |
| `"reasoning"` | `{ text }` |
| `"file"` | `{ mediaType, url }` (`FileUIPart`) |
| `"tool-<toolName>"` | Typed tool part with `state` and `input`/`output` |
| `"dynamic-tool"` | Tool part for tools not known at compile time |
| `"data-<name>"` | Custom data part (Prowler uses `data-chain-of-thought`) |

```typescript
import type { UIMessage } from "ai";

const getText = (message: UIMessage) =>
  message.parts
    .filter((p) => p.type === "text")
    .map((p) => p.text)
    .join("");
```

## Server: Custom UI Message Stream (Prowler pattern)

When the model runs outside the AI SDK (LangGraph), emit UI message chunks yourself:

```typescript
import { createUIMessageStreamResponse, type UIMessage } from "ai";

export async function POST(req: Request) {
  const { messages }: { messages: UIMessage[] } = await req.json();

  const stream = new ReadableStream({
    async start(controller) {
      controller.enqueue({ type: "text-start", id: "msg" });
      controller.enqueue({ type: "text-delta", id: "msg", delta: "Hello" });
      controller.enqueue({ type: "data-chain-of-thought", data: { action: "start" } });
      controller.enqueue({ type: "text-end", id: "msg" });
      controller.close();
    },
  });

  return createUIMessageStreamResponse({ stream });
}
```

Every `text-delta` must sit between a `text-start` and `text-end` with the same `id`.
Authenticate first (`await auth()` from `@/auth.config`) and return 401 without a session, as the analyst route does.

## Server: streamText (only if an AI SDK provider is added)

```typescript
import { convertToModelMessages, streamText, tool, type UIMessage } from "ai";
import { z } from "zod";

const result = streamText({            // not awaited
  model,                               // a provider model instance
  messages: await convertToModelMessages(messages),
  tools: {
    getFinding: tool({
      description: "Get a finding by id",
      inputSchema: z.object({ id: z.string() }), // `inputSchema`, not `parameters`
      execute: async ({ id }) => ({ id }),
    }),
  },
});

return result.toUIMessageStreamResponse(); // not toDataStreamResponse (v4)
```

## Commands

```bash
cd ui && pnpm run typecheck
cd ui && pnpm exec vitest run --project unit lib/lighthouse-v1 components/lighthouse-v1
```
