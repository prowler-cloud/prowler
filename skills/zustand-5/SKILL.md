---
name: zustand-5
description: >
  Zustand 5 state management patterns.
  Trigger: When implementing client-side state with Zustand (stores, selectors, persist middleware, slices).
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, ui]
  auto_invoke: "Using Zustand stores"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash, WebFetch, WebSearch, Task
---

## Prowler UI Layout

- Stores live in `ui/store/{feature}/store.ts` (some single files, e.g. `ui/store/side-panel.ts`) and are re-exported from `ui/store/index.ts`.
- Tests: `ui/store/__tests__/*.test.ts` or co-located `store.test.ts`.
- `zustand/middleware` (`persist`, `createJSONStorage`) is used; `immer` is NOT installed in `ui/`.

## Basic Store

```typescript
import { create } from "zustand";

interface CounterStore {
  count: number;
  increment: () => void;
  decrement: () => void;
  reset: () => void;
}

const useCounterStore = create<CounterStore>((set) => ({
  count: 0,
  increment: () => set((state) => ({ count: state.count + 1 })),
  decrement: () => set((state) => ({ count: state.count - 1 })),
  reset: () => set({ count: 0 }),
}));

// Usage - select what you need
function Counter() {
  const count = useCounterStore((s) => s.count);
  const increment = useCounterStore((s) => s.increment);
  const decrement = useCounterStore((s) => s.decrement);
  return (
    <div>
      <span>{count}</span>
      <button onClick={increment}>+</button>
      <button onClick={decrement}>-</button>
    </div>
  );
}
```

## Persist Middleware

```typescript
import { create } from "zustand";
import { persist } from "zustand/middleware";

interface SettingsStore {
  theme: "light" | "dark";
  language: string;
  setTheme: (theme: "light" | "dark") => void;
  setLanguage: (language: string) => void;
}

const useSettingsStore = create<SettingsStore>()(
  persist(
    (set) => ({
      theme: "light",
      language: "en",
      setTheme: (theme) => set({ theme }),
      setLanguage: (language) => set({ language }),
    }),
    {
      name: "settings-storage",  // localStorage key
    }
  )
);
```

## Selectors (Zustand 5)

```typescript
// ✅ Select specific fields to prevent unnecessary re-renders
function UserName() {
  const name = useUserStore((state) => state.name);
  return <span>{name}</span>;
}

// ✅ For multiple fields, use useShallow
import { useShallow } from "zustand/react/shallow";

function UserInfo() {
  const { name, email } = useUserStore(
    useShallow((state) => ({ name: state.name, email: state.email }))
  );
  return <div>{name} - {email}</div>;
}

// ❌ AVOID: Selecting entire store (causes re-render on any change)
const store = useUserStore();  // Re-renders on ANY state change

// ❌ v5 BREAKS: selector returning a new object/array without useShallow
// -> "Maximum update depth exceeded" (v5 `create` hooks compare with Object.is and take no equalityFn)
const { name, email } = useUserStore((s) => ({ name: s.name, email: s.email }));
```

## Async Actions

```typescript
interface UserStore {
  user: User | null;
  loading: boolean;
  error: string | null;
  fetchUser: (id: string) => Promise<void>;
}

const useUserStore = create<UserStore>((set) => ({
  user: null,
  loading: false,
  error: null,

  fetchUser: async (id) => {
    set({ loading: true, error: null });
    try {
      const response = await fetch(`/api/users/${id}`);
      const user = await response.json();
      set({ user, loading: false });
    } catch (error) {
      set({ error: "Failed to fetch user", loading: false });
    }
  },
}));
```

## Slices Pattern

```typescript
import { create, type StateCreator } from "zustand";

// userSlice.ts
interface UserSlice {
  user: User | null;
  setUser: (user: User) => void;
  clearUser: () => void;
}

const createUserSlice: StateCreator<UserSlice & CartSlice, [], [], UserSlice> = (set) => ({
  user: null,
  setUser: (user) => set({ user }),
  clearUser: () => set({ user: null }),
});

// cartSlice.ts
interface CartSlice {
  items: CartItem[];
  addItem: (item: CartItem) => void;
  removeItem: (id: string) => void;
}

const createCartSlice: StateCreator<UserSlice & CartSlice, [], [], CartSlice> = (set) => ({
  items: [],
  addItem: (item) => set((state) => ({ items: [...state.items, item] })),
  removeItem: (id) => set((state) => ({
    items: state.items.filter(i => i.id !== id)
  })),
});

// store.ts
type Store = UserSlice & CartSlice;

const useStore = create<Store>()((...args) => ({
  ...createUserSlice(...args),
  ...createCartSlice(...args),
}));
```

## DevTools

```typescript
import { create } from "zustand";
import { devtools } from "zustand/middleware";

const useStore = create<Store>()(
  devtools(
    (set) => ({
      // store definition
    }),
    { name: "MyStore" }  // Name in Redux DevTools
  )
);
```

## Outside React

```typescript
// Access store outside components
const { count, increment } = useCounterStore.getState();
increment();

// Subscribe to changes
const unsubscribe = useCounterStore.subscribe(
  (state) => console.log("Count changed:", state.count)
);
```
