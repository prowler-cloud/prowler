
import { tool } from "@opencode-ai/plugin"

const SKILL = `
---
name: zustand-5
description: Zustand 5 state management patterns. Persist, selectors, slices, middleware.
license: MIT
---

## When to use this skill

Use this skill for Zustand 5 state management in React.

## Basic Store

\`\`\`typescript
import { create } from "zustand";

interface CounterStore {
  count: number;
  increment: () => void;
  decrement: () => void;
}

const useCounterStore = create<CounterStore>((set) => ({
  count: 0,
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
}));

// Usage
function Counter() {
  const { count, increment } = useCounterStore();
  return <button onClick={increment}>{count}</button>;
}
\`\`\`

## Persist Middleware

\`\`\`typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";

const useSettingsStore = create(
  persist(
    (set) => ({
      theme: "light",
      setTheme: (theme) => set({ theme }),
    }),
    { name: "settings-storage" }  // localStorage key
  )
);
\`\`\`

## Selectors (Zustand 5)

\`\`\`typescript
// ✅ Select specific fields
const name = useUserStore((state) => state.name);

// ✅ Multiple fields with useShallow
import { useShallow } from "zustand/react/shallow";

const { name, email } = useUserStore(
  useShallow((state) => ({ name: state.name, email: state.email }))
);

// ❌ AVOID: Entire store
const store = useUserStore();  // Re-renders on ANY change
\`\`\`

## Async Actions

\`\`\`typescript
const useUserStore = create((set) => ({
  user: null,
  loading: false,

  fetchUser: async (id) => {
    set({ loading: true });
    const user = await fetch(\\\`/api/users/\\\${id}\\\`).then(r => r.json());
    set({ user, loading: false });
  },
}));
\`\`\`

## Slices Pattern

\`\`\`typescript
const createUserSlice = (set) => ({
  user: null,
  setUser: (user) => set({ user }),
});

const createCartSlice = (set) => ({
  items: [],
  addItem: (item) => set((s) => ({ items: [...s.items, item] })),
});

const useStore = create((...args) => ({
  ...createUserSlice(...args),
  ...createCartSlice(...args),
}));
\`\`\`

## Keywords
zustand, state management, react, store, persist
`;

export default tool({
  description: SKILL,
  args: {
    topic: tool.schema.string().describe("Topic: basic, persist, selectors, async, slices"),
  },
  async execute(args) {
    const topic = args.topic.toLowerCase();

    if (topic.includes("persist")) {
      return `
## Zustand Persist

\`\`\`typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";

const useStore = create(
  persist(
    (set) => ({
      value: 0,
      setValue: (value) => set({ value }),
    }),
    {
      name: "storage-key",  // localStorage key
      partialize: (state) => ({ value: state.value }),  // Only persist some fields
    }
  )
);
\`\`\`
      `.trim();
    }

    if (topic.includes("selector")) {
      return `
## Zustand 5 Selectors

\`\`\`typescript
// ✅ Single field
const count = useStore((s) => s.count);

// ✅ Multiple fields
import { useShallow } from "zustand/react/shallow";
const { a, b } = useStore(useShallow((s) => ({ a: s.a, b: s.b })));

// ❌ Never select entire store
const store = useStore();  // Re-renders on ANY change
\`\`\`
      `.trim();
    }

    return `
## Zustand 5 Quick Reference

\`\`\`typescript
// Basic store
const useStore = create((set) => ({
  count: 0,
  increment: () => set((s) => ({ count: s.count + 1 })),
}));

// Persist
import { persist } from "zustand/middleware";
create(persist((set) => ({ ... }), { name: "key" }));

// Selectors
const count = useStore((s) => s.count);

// Outside React
useStore.getState().increment();
\`\`\`
    `.trim();
  },
})
