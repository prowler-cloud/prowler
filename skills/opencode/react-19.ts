
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: react-19
description: React 19 patterns with React Compiler. No useMemo/useCallback, async components, use() hook.
license: MIT
---

## When to use this skill

Use this skill for React 19+ projects with React Compiler enabled.

## Critical Rules

### No Manual Memoization (REQUIRED)

\`\`\`typescript
// ✅ React Compiler handles optimization automatically
function Component({ items }) {
  const filtered = items.filter(x => x.active);
  const sorted = filtered.sort((a, b) => a.name.localeCompare(b.name));

  const handleClick = (id) => {
    console.log(id);
  };

  return <List items={sorted} onClick={handleClick} />;
}

// ❌ NEVER: Manual memoization (compiler does this)
const filtered = useMemo(() => items.filter(x => x.active), [items]);
const handleClick = useCallback((id) => console.log(id), []);
\`\`\`

### Imports (REQUIRED)

\`\`\`typescript
// ✅ ALWAYS: Named imports from react
import { useState, useEffect, useRef } from "react";

// ❌ NEVER: Default or namespace imports
import React from "react";
import * as React from "react";
\`\`\`

### Server Components First

\`\`\`typescript
// ✅ Server Component (default) - no directive needed
export default async function Page() {
  const data = await fetchData();  // Direct async/await
  return <ClientComponent data={data} />;
}

// ✅ Client Component - only when needed
"use client";
export function InteractiveComponent() {
  const [state, setState] = useState(false);
  return <button onClick={() => setState(!state)}>Toggle</button>;
}
\`\`\`

### When to use "use client"

\`\`\`typescript
// Need "use client" for:
// - useState, useEffect, useRef, useContext
// - Event handlers (onClick, onChange, etc.)
// - Browser APIs (window, localStorage)
// - Custom hooks that use above

// DON'T need "use client" for:
// - Data fetching
// - Static rendering
// - Components that just receive props and render
\`\`\`

### use() Hook (React 19)

\`\`\`typescript
// ✅ Read promises and context with use()
import { use } from "react";

function Comments({ commentsPromise }) {
  const comments = use(commentsPromise);  // Suspends until resolved
  return comments.map(c => <Comment key={c.id} {...c} />);
}

// ✅ Conditional context reading
function Component({ showTheme }) {
  if (showTheme) {
    const theme = use(ThemeContext);  // Can be conditional!
    return <div style={{ color: theme.primary }}>Themed</div>;
  }
  return <div>Not themed</div>;
}
\`\`\`

### Actions (Form Handling)

\`\`\`typescript
// ✅ Server Action
async function submitForm(formData: FormData) {
  "use server";
  const name = formData.get("name");
  await saveToDatabase({ name });
  revalidatePath("/");
}

// ✅ Form with action
function Form() {
  return (
    <form action={submitForm}>
      <input name="name" />
      <button type="submit">Submit</button>
    </form>
  );
}

// ✅ useActionState for pending state
import { useActionState } from "react";

function Form() {
  const [state, action, isPending] = useActionState(submitForm, null);

  return (
    <form action={action}>
      <button disabled={isPending}>
        {isPending ? "Saving..." : "Save"}
      </button>
    </form>
  );
}
\`\`\`

### useOptimistic

\`\`\`typescript
import { useOptimistic } from "react";

function Messages({ messages }) {
  const [optimisticMessages, addOptimistic] = useOptimistic(
    messages,
    (state, newMessage) => [...state, { ...newMessage, sending: true }]
  );

  async function send(formData) {
    const message = formData.get("message");
    addOptimistic({ text: message });  // Instant UI update
    await sendMessage(message);        // Actual send
  }

  return (
    <>
      {optimisticMessages.map(m => (
        <div key={m.id} style={{ opacity: m.sending ? 0.5 : 1 }}>
          {m.text}
        </div>
      ))}
      <form action={send}>
        <input name="message" />
      </form>
    </>
  );
}
\`\`\`

### ref as Prop (React 19)

\`\`\`typescript
// ✅ React 19: ref is just a prop, no forwardRef needed
function Input({ ref, ...props }) {
  return <input ref={ref} {...props} />;
}

// Usage
function Parent() {
  const inputRef = useRef(null);
  return <Input ref={inputRef} placeholder="Type..." />;
}

// ❌ Old way (still works but unnecessary)
const Input = forwardRef((props, ref) => (
  <input ref={ref} {...props} />
));
\`\`\`

## Keywords
react, react 19, compiler, useMemo, useCallback, server components, use hook, actions
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: compiler, server-components, use-hook, actions, optimistic"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("compiler") || topic.includes("memo")) {
      return `
## React Compiler - No Manual Memoization

React 19 Compiler automatically optimizes:
- Expensive calculations
- Callback functions
- Object/array creation

\`\`\`typescript
// ✅ Just write normal code
function Component({ items, onSelect }) {
  const filtered = items.filter(x => x.active);
  const handleClick = (id) => onSelect(id);

  return <List items={filtered} onClick={handleClick} />;
}

// ❌ REMOVE these - compiler handles it
const filtered = useMemo(() => ..., [items]);
const handleClick = useCallback(() => ..., [onSelect]);
\`\`\`

The compiler analyzes your code and adds memoization where needed.
      `.trim();
    }

    if (topic.includes("server") || topic.includes("client")) {
      return `
## Server vs Client Components

\`\`\`typescript
// SERVER (default) - no directive
export default async function Page() {
  const data = await db.query();  // Direct DB access
  return <ClientPart data={data} />;
}

// CLIENT - only when needed
"use client";
export function ClientPart({ data }) {
  const [selected, setSelected] = useState(null);
  return <button onClick={() => setSelected(data.id)}>Select</button>;
}
\`\`\`

**Use "use client" only for:**
- useState, useEffect, useRef
- Event handlers (onClick, onChange)
- Browser APIs (window, localStorage)
      `.trim();
    }

    if (topic.includes("use") && !topic.includes("usememo")) {
      return `
## use() Hook - React 19

\`\`\`typescript
import { use } from "react";

// Read promises (suspends until resolved)
function Comments({ promise }) {
  const comments = use(promise);
  return comments.map(c => <div key={c.id}>{c.text}</div>);
}

// Conditional context (not possible with useContext!)
function Theme({ showTheme }) {
  if (showTheme) {
    const theme = use(ThemeContext);
    return <div style={{ color: theme.primary }}>Themed</div>;
  }
  return <div>Plain</div>;
}
\`\`\`
      `.trim();
    }

    return `
## React 19 Quick Reference

1. **No useMemo/useCallback** - Compiler handles it
2. **Imports**: \`import { useState } from "react"\`
3. **Server Components** by default, "use client" only when needed
4. **use() hook** for promises and conditional context
5. **Actions** for form handling with useActionState
6. **ref as prop** - no forwardRef needed

Topics: compiler, server-components, use-hook, actions, optimistic
    `.trim();
  },
})
