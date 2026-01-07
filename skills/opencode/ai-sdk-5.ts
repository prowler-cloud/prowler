
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: ai-sdk-5
description: Vercel AI SDK 5 patterns. Breaking changes from v4, UIMessage, streaming.
license: MIT
---

## When to use this skill

Use this skill for AI SDK 5 - note breaking changes from v4.

## Breaking Changes from AI SDK 4

\`\`\`typescript
// ❌ AI SDK 4 (OLD)
import { useChat } from "ai";
const { messages, handleSubmit, input, handleInputChange } = useChat({
  api: "/api/chat",
});

// ✅ AI SDK 5 (NEW)
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";

const { messages, sendMessage } = useChat({
  transport: new DefaultChatTransport({ api: "/api/chat" }),
});
// Manual input state required
const [input, setInput] = useState("");
\`\`\`

## Client Setup

\`\`\`typescript
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";
import { useState } from "react";

export function Chat() {
  const [input, setInput] = useState("");

  const { messages, sendMessage, isLoading } = useChat({
    transport: new DefaultChatTransport({ api: "/api/chat" }),
  });

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!input.trim()) return;
    sendMessage({ text: input });
    setInput("");
  };

  return (
    <form onSubmit={handleSubmit}>
      <input value={input} onChange={(e) => setInput(e.target.value)} />
      <button disabled={isLoading}>Send</button>
    </form>
  );
}
\`\`\`

## UIMessage Structure (v5)

\`\`\`typescript
// ❌ Old: message.content was a string
// ✅ New: message.parts is an array

interface UIMessage {
  id: string;
  role: "user" | "assistant";
  parts: MessagePart[];
}

// Extract text
function getMessageText(message) {
  return message.parts
    .filter(p => p.type === "text")
    .map(p => p.text)
    .join("");
}
\`\`\`

## Server-Side

\`\`\`typescript
// app/api/chat/route.ts
import { openai } from "@ai-sdk/openai";
import { streamText } from "ai";

export async function POST(req) {
  const { messages } = await req.json();

  const result = await streamText({
    model: openai("gpt-4o"),
    messages,
  });

  return result.toDataStreamResponse();
}
\`\`\`

## Keywords
ai sdk, vercel ai, chat, streaming, llm
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: migration, client, server, messages, langchain"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("migrat") || topic.includes("v4") || topic.includes("break")) {
      return `
## AI SDK 4 → 5 Migration

\`\`\`typescript
// Import
"ai" → "@ai-sdk/react"

// useChat
useChat({ api: "/api/chat" })
→ useChat({ transport: new DefaultChatTransport({ api: "/api/chat" }) })

// No more handleSubmit, handleInputChange
// Manual state: const [input, setInput] = useState("")
// Use sendMessage({ text: input })

// Message structure
message.content (string) → message.parts (array)
\`\`\`
      `.trim();
    }

    if (topic.includes("message")) {
      return `
## UIMessage Structure (v5)

\`\`\`typescript
interface UIMessage {
  id: string;
  role: "user" | "assistant";
  parts: Array<
    | { type: "text"; text: string }
    | { type: "image"; image: string }
    | { type: "tool-call"; toolName: string; args: unknown }
  >;
}

// Extract text
const text = message.parts
  .filter(p => p.type === "text")
  .map(p => p.text)
  .join("");
\`\`\`
      `.trim();
    }

    return `
## AI SDK 5 Quick Reference

\`\`\`typescript
// Client
import { useChat } from "@ai-sdk/react";
import { DefaultChatTransport } from "ai";

const { messages, sendMessage, isLoading } = useChat({
  transport: new DefaultChatTransport({ api: "/api/chat" }),
});

// Server
import { streamText } from "ai";
import { openai } from "@ai-sdk/openai";

const result = await streamText({
  model: openai("gpt-4o"),
  messages,
});
return result.toDataStreamResponse();
\`\`\`
    `.trim();
  },
})
