---
name: no-use-effect
description: >
  No direct useEffect in React components: derive state, use event handlers, Server Components, use(), key resets, useSyncExternalStore, useEffectEvent or useMountEffect instead. React Compiler aware (no useMemo/useCallback).
  Trigger: When writing, editing or reviewing React components or hooks in ui/, when about to write useEffect or useLayoutEffect, or when syncing state with props, URL params or loaded data.
license: Apache-2.0
metadata:
  author: prowler-cloud
  version: "1.1"
  scope: [root, ui]
  auto_invoke:
    - "Adding, changing or reviewing a React effect"
    - "Syncing React state with props, URL params or loaded data"
allowed-tools: Read, Edit, Write, Glob, Grep, Bash
---

# No Direct useEffect

Components never call `useEffect` directly. Most effects should not exist: the value can be derived in render, the work belongs in an event handler, or the data comes from the server. For the rare real sync with an external system, use a named hook.

## Prowler UI Context

- React 19.2 with the React Compiler (`reactCompiler: true` in `ui/next.config.js`). Never write `useMemo`, `useCallback` or `memo`; lint rejects them.
- Data comes from Server Components and server actions. There is no client data-fetching library: pass data (or a promise unwrapped with `use()`) from the server instead of fetching in an effect.
- `useMountEffect` lives in `ui/hooks/use-mount-effect.ts`. `useEffectEvent` is stable (see `ui/components/registry/use-registry-refresh.ts`). `useSyncExternalStore` example: `ui/hooks/use-media-query.ts`.
- Lint enforces part of this (`react-hooks/set-state-in-effect`, `react-hooks/refs`, `react-hooks/purity`). Existing violations are frozen in `ui/eslint-suppressions.json`; do not add new entries.
- Effects that sync with a real external system are fine inside a named hook: `EventSource`, `matchMedia`, `ResizeObserver`, timers, third-party widgets. Moving avoidable state sync into a custom hook is not a fix.

```tsx
// ui/hooks/use-mount-effect.ts
export function useMountEffect(effect: EffectCallback) {
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(effect, []);
}
```

## The 6 Rules

### Rule 1: Derive state, do not sync it

If it can be calculated from existing state or props, compute it in render. The compiler caches it.

```tsx
// BAD: two renders, and the copy drifts
const [visible, setVisible] = useState([]);
useEffect(() => {
  setVisible(findings.filter((f) => !f.muted));
}, [findings]);

// GOOD
const visible = findings.filter((f) => !f.muted);
```

State that refers to server data stores only the user's intent (an id) and derives the effective value in render.

**Smell test:** `useEffect(() => setX(f(y)), [y])`, or state that only mirrors props, search params or query results.

### Rule 2: Fetch on the server, not in effects

Effect-based fetching races and reinvents caching. Fetch in the Server Component (or a server action) and pass the result down. To stream, pass the promise and unwrap it with `use()` inside `<Suspense>`.

```tsx
// GOOD: Server Component
export default async function Page() {
  const providers = await getProviders();
  return <ProvidersTable providers={providers} />;
}

// GOOD: client child unwraps a promise passed from the server
function Overview({ overviewPromise }: { overviewPromise: Promise<Overview> }) {
  const overview = use(overviewPromise);
  return <OverviewCards overview={overview} />;
}
```

**Smell test:** an effect that calls `fetch()` or a server action and then `setState()`.

### Rule 3: Event handlers, not effects

If a user action triggers it, do the work in the handler. Validate, transform, submit, then update state, all in the handler.

```tsx
// BAD: flag relay through an effect
const [submitted, setSubmitted] = useState(false);
useEffect(() => {
  if (submitted) {
    saveRule(values);
    setSubmitted(false);
  }
}, [submitted]);

// GOOD
const handleSubmit = async () => {
  await saveRule(values);
};
```

Shared logic between handlers is a function, not an effect.

**Smell test:** state used as a flag so an effect can do the real work.

### Rule 4: useMountEffect for one-time external sync

Only for real mount-time setup with an external system. Gate the mount instead of guarding inside the effect.

```tsx
// BAD: guard inside the effect
useEffect(() => {
  if (!isLoading) startTour();
}, [isLoading]);

// GOOD: mount when ready
function TourGate({ isLoading }: { isLoading: boolean }) {
  if (isLoading) return <TourSkeleton />;
  return <Tour />;
}

function Tour() {
  useMountEffect(() => startTour());
  return null;
}
```

**Smell test:** the behavior is "set up on mount, clean up on unmount" with something outside React.

### Rule 5: Reset with key, not dependency choreography

To start fresh when an id changes, remount with `key`. `ui/app/(prowler)/lighthouse/page.tsx` keys the chat by session this way.

```tsx
// BAD
useEffect(() => {
  setDraft("");
  setSelection([]);
}, [sessionId]);

// GOOD
<ChatPanel key={sessionId} sessionId={sessionId} />
```

**Smell test:** the effect's only job is resetting local state when a prop changes.

### Rule 6: Never patch a broken effect with a ref

A ref that stops an effect from double-firing, looping or reading stale state hides the real problem. Remove the effect.

```tsx
// BAD: ref guard
const hasRun = useRef(false);
useEffect(() => {
  if (hasRun.current) return;
  hasRun.current = true;
  trackPageView(page);
}, [page]);

// GOOD
useMountEffect(() => trackPageView(page));
```

```tsx
// BAD: ref to read the latest callback
const onMessageRef = useRef(onMessage);
onMessageRef.current = onMessage;
useEffect(() => {
  const source = new EventSource(url);
  source.onmessage = (event) => onMessageRef.current(event);
  return () => source.close();
}, [url]);

// GOOD: useEffectEvent reads the latest props; the effect lives in a named hook
function useEventSource(url: string, onMessage: (event: MessageEvent) => void) {
  const handleMessage = useEffectEvent((event: MessageEvent) => onMessage(event));
  useEffect(() => {
    const source = new EventSource(url);
    source.onmessage = handleMessage;
    return () => source.close();
  }, [url]);
}
```

Call the function `useEffectEvent` returns only from inside effects, never during render or as a prop.

**Smell test:** `hasRun.current`, `isMounted.current`, or a ref whose only job is controlling when an effect runs.

## Other Patterns

- **Notify parents in the handler.** Update local state and call `onChange` in the same event, or lift the state up. Never `useEffect(() => onChange(value), [value])`.
- **Subscribe with `useSyncExternalStore`** for browser APIs and external stores, as `ui/hooks/use-media-query.ts` does.
- **Callback refs for DOM work.** Measure or set up a node in a callback ref written as a plain function; React 19 lets it return a cleanup.
- **No effect chains.** Derive values in render and batch updates in the event handler instead of effects that trigger each other.
- **react-hook-form under the compiler.** Read values with `useWatch({ control, name })` and validity with `useFormState({ control })`. A cached `form.formState.<field>` read goes stale, and `form.watch()` makes the compiler skip the component. Seed a form only where its initial values are ready; while data loads, the form lives deeper in the tree.

## Decision Checklist

1. Can I compute it during render? Derive it.
2. Is it triggered by a user action? Event handler.
3. Am I loading data? Server Component, server action, or `use()` with Suspense.
4. Am I subscribing to an external store or browser API? `useSyncExternalStore`.
5. Do I need to reset state when a prop changes? `key`.
6. Is it real mount-time external sync? `useMountEffect`, or a named hook with cleanup.
7. Am I using refs to control when an effect runs? Remove them; use a handler, derive, or `useEffectEvent`.
8. Do I need a DOM side effect when a node mounts? Callback ref.

If none apply and you still need an effect, read [references/patterns.md](references/patterns.md), put the effect in a named hook with cleanup, and say why in one line.

## Reviewing Effects

Flag effects that derive state, relay events, mirror props or query data, or reset on id change, and name the replacement. Before flagging, show an alternative that keeps the required timing, updates and cleanup. Do not flag effects that sync with a real external system.

## Commands

```bash
cd ui
pnpm run lint:check       # react-hooks compiler rules + restricted imports
pnpm run test:integration # the only Vitest project compiled with the React Compiler
```

## Resources

- [references/patterns.md](references/patterns.md): longer examples for each rule
- [You Might Not Need an Effect](https://react.dev/learn/you-might-not-need-an-effect)
