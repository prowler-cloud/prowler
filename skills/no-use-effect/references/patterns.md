# Detailed Patterns & Examples

Extended examples for each rule when the SKILL.md summary isn't enough.

These examples are framework-neutral. In Prowler UI the React Compiler is on, so skip the `useMemo`/`useCallback` variants, and data comes from Server Components or server actions rather than a client fetching library.

## Table of Contents

- [Derived State](#derived-state)
- [Expensive Calculations](#expensive-calculations)
- [Data Fetching Race Conditions](#data-fetching-race-conditions)
- [Event Handler Extraction](#event-handler-extraction)
- [Conditional Mounting](#conditional-mounting)
- [Key-Based Reset](#key-based-reset)
- [Adjusting State on Prop Change](#adjusting-state-on-prop-change)
- [Effect Chains](#effect-chains)
- [Parent Notification](#parent-notification)
- [External Store Subscription](#external-store-subscription)
- [App Initialization](#app-initialization)
- [Effect-Ref Debt Spiral](#effect-ref-debt-spiral)
- [useEffectEvent](#useeffectevent)
- [Callback Refs](#callback-refs)

---

## Derived State

### Chained derived values

```tsx
// BAD: effect chain for tax/total
function Cart({ subtotal }) {
  const [tax, setTax] = useState(0);
  const [total, setTotal] = useState(0);

  useEffect(() => { setTax(subtotal * 0.1); }, [subtotal]);
  useEffect(() => { setTotal(subtotal + tax); }, [subtotal, tax]);
}

// GOOD: inline computation
function Cart({ subtotal }) {
  const tax = subtotal * 0.1;
  const total = subtotal + tax;
}
```

### fullName from firstName + lastName

```tsx
// BAD
const [fullName, setFullName] = useState('');
useEffect(() => {
  setFullName(firstName + ' ' + lastName);
}, [firstName, lastName]);

// GOOD
const fullName = firstName + ' ' + lastName;
```

---

## Expensive Calculations

```tsx
// BAD
const [visibleTodos, setVisibleTodos] = useState([]);
useEffect(() => {
  setVisibleTodos(getFilteredTodos(todos, filter));
}, [todos, filter]);

// GOOD (React Compiler): inline, the compiler caches it
const visibleTodos = getFilteredTodos(todos, filter);

// GOOD (no React Compiler): useMemo
const visibleTodos = useMemo(
  () => getFilteredTodos(todos, filter),
  [todos, filter]
);
```

**When is a calculation expensive?** Measure with `console.time`. Generally only worth memoizing if >1ms on throttled CPU. With React Compiler this question goes away: never add `useMemo` by hand.

---

## Data Fetching Race Conditions

### The problem with bare fetch in effects

User types "hello" fast. Requests fire for "h", "he", "hel", "hell", "hello". Response for "hell" may arrive after "hello", showing wrong results.

### If you must use an effect for fetching (no library available)

Encapsulate in a custom hook — never use `useEffect` directly in a component. Always add cleanup:

### Extract into a custom hook

```tsx
function useData(url) {
  const [data, setData] = useState(null);
  useEffect(() => {
    let ignore = false;
    fetch(url)
      .then(r => r.json())
      .then(json => { if (!ignore) setData(json); });
    return () => { ignore = true; };
  }, [url]);
  return data;
}
```

**Note:** `useEffect` inside a custom hook like `useData` is the accepted escape hatch — the rule bans direct `useEffect` in components, not in reusable hooks that encapsulate side effects behind a clean interface.

### Best: use a data-fetching library

React Query, SWR, TanStack Query, or framework-provided fetching. These handle caching, deduplication, cancellation, retries, background refetching, stale-while-revalidate, and SSR hydration.

---

## Event Handler Extraction

### Shared logic between multiple handlers

```tsx
// BAD: effect watches product.isInCart
useEffect(() => {
  if (product.isInCart) {
    showNotification(`Added ${product.name}!`);
  }
}, [product]);

// GOOD: shared function called from handlers
function buyProduct() {
  addToCart(product);
  showNotification(`Added ${product.name}!`);
}

function handleBuyClick() { buyProduct(); }
function handleCheckoutClick() { buyProduct(); navigateTo('/checkout'); }
```

### Form submission

```tsx
// BAD: effect watches jsonToSubmit
const [jsonToSubmit, setJsonToSubmit] = useState(null);
useEffect(() => {
  if (jsonToSubmit !== null) post('/api/register', jsonToSubmit);
}, [jsonToSubmit]);

// GOOD: submit in the handler
function handleSubmit(e) {
  e.preventDefault();
  post('/api/register', { firstName, lastName });
}
```

### Analytics vs. user actions

Analytics that fire "because the component was displayed" are valid for `useMountEffect`. Form submission that fires "because the user clicked submit" belongs in the handler.

---

## Conditional Mounting

Instead of guarding inside an effect, control mounting in the parent:

```tsx
// BAD
function VideoPlayer({ isLoading }) {
  useEffect(() => {
    if (!isLoading) playVideo();
  }, [isLoading]);
}

// GOOD: parent controls when to mount
function VideoPlayerWrapper({ isLoading }) {
  if (isLoading) return <LoadingScreen />;
  return <VideoPlayer />;
}

function VideoPlayer() {
  useMountEffect(() => playVideo());
}
```

### Persistent shell + conditional instance

When you need a persistent container but conditional behavior:

```tsx
function VideoPlayerContainer({ isLoading }) {
  return (
    <>
      <VideoPlayerShell isLoading={isLoading} />
      {!isLoading && <VideoPlayerInstance />}
    </>
  );
}

function VideoPlayerInstance() {
  useMountEffect(() => playVideo());
}
```

---

## Key-Based Reset

### Resetting all state when entity changes

```tsx
// BAD
function ProfilePage({ userId }) {
  const [comment, setComment] = useState('');
  useEffect(() => { setComment(''); }, [userId]);
}

// GOOD: key forces full reset
function ProfilePage({ userId }) {
  return <Profile userId={userId} key={userId} />;
}

function Profile({ userId }) {
  const [comment, setComment] = useState('');
  // Fresh state on each userId change
}
```

### Resetting form state

```tsx
// BAD: effect clears form fields
useEffect(() => {
  setName('');
  setEmail('');
  setNotes('');
}, [contactId]);

// GOOD
<EditForm key={contactId} contact={contact} />
```

---

## Adjusting State on Prop Change

When you only need to adjust some state (not reset everything):

### Best: derive it during render

```tsx
function List({ items, onRemove }) {
  const [selectedId, setSelectedId] = useState(null);
  // A missing item shows no selection; selectedId still holds its id
  const selection = items.find(item => item.id === selectedId) ?? null;

  function handleRemove(id) {
    onRemove(id);
    // Forget the id too, so the item is not reselected if it comes back
    if (id === selectedId) setSelectedId(null);
  }
}
```

### Acceptable: adjust during render with previous props tracking

```tsx
function List({ items }) {
  const [isReverse, setIsReverse] = useState(false);
  const [selection, setSelection] = useState(null);
  const [prevItems, setPrevItems] = useState(items);

  if (items !== prevItems) {
    setPrevItems(items);
    setSelection(null);
  }
}
```

---

## Effect Chains

### The game card example

```tsx
// BAD: 4 effects chaining state updates = 4 extra renders
useEffect(() => { if (card?.gold) setGoldCardCount(c => c + 1); }, [card]);
useEffect(() => { if (goldCardCount > 3) { setRound(r => r + 1); setGoldCardCount(0); } }, [goldCardCount]);
useEffect(() => { if (round > 5) setIsGameOver(true); }, [round]);
useEffect(() => { if (isGameOver) alert('Good game!'); }, [isGameOver]);

// GOOD: all logic in the event handler, derived state inline
const isGameOver = round > 5;

function handlePlaceCard(nextCard) {
  if (isGameOver) throw Error('Game already ended.');
  setCard(nextCard);
  if (nextCard.gold) {
    if (goldCardCount < 3) {
      setGoldCardCount(goldCardCount + 1);
    } else {
      setGoldCardCount(0);
      setRound(round + 1);
      if (round === 5) alert('Good game!');
    }
  }
}
```

---

## Parent Notification

### Option A: update both in same event

```tsx
function Toggle({ onChange }) {
  const [isOn, setIsOn] = useState(false);

  function updateToggle(nextIsOn) {
    setIsOn(nextIsOn);
    onChange(nextIsOn);
  }

  return <button onClick={() => updateToggle(!isOn)}>Toggle</button>;
}
```

### Option B: fully controlled component (preferred)

```tsx
function Toggle({ isOn, onChange }) {
  return <button onClick={() => onChange(!isOn)}>Toggle</button>;
}
```

### Passing data to parent

```tsx
// BAD: child fetches, then notifies parent via effect
useEffect(() => { if (data) onFetched(data); }, [onFetched, data]);

// GOOD: parent owns the fetch, passes data down
function Parent() {
  const data = useSomeAPI();
  return <Child data={data} />;
}
```

---

## External Store Subscription

```tsx
// BAD: manual subscription
useEffect(() => {
  const handler = () => setIsOnline(navigator.onLine);
  window.addEventListener('online', handler);
  window.addEventListener('offline', handler);
  return () => {
    window.removeEventListener('online', handler);
    window.removeEventListener('offline', handler);
  };
}, []);

// GOOD: useSyncExternalStore
function subscribe(callback) {
  window.addEventListener('online', callback);
  window.addEventListener('offline', callback);
  return () => {
    window.removeEventListener('online', callback);
    window.removeEventListener('offline', callback);
  };
}

function useOnlineStatus() {
  return useSyncExternalStore(
    subscribe,
    () => navigator.onLine,
    () => true // SSR fallback
  );
}
```

---

## App Initialization

```tsx
// BAD: runs twice in dev, can invalidate tokens
useEffect(() => {
  loadDataFromLocalStorage();
  checkAuthToken();
}, []);

// GOOD option 1: module-level
if (typeof window !== 'undefined') {
  checkAuthToken();
  loadDataFromLocalStorage();
}

// GOOD option 2: guard variable with useMountEffect
let didInit = false;
function App() {
  useMountEffect(() => {
    if (!didInit) {
      didInit = true;
      loadDataFromLocalStorage();
      checkAuthToken();
    }
  });
}
```

---

## Effect-Ref Debt Spiral

When a `useEffect` causes problems (double-firing, stale closures, loops), developers often "patch" it with a `useRef` instead of fixing the root cause. This creates a brittle hybrid where two state systems compete: one React tracks (useState) and one it doesn't (useRef). The fix is always to eliminate the effect, not to bandage it.

### `hasRun` guard to prevent double-fire

```tsx
// BAD: ref guard hides the real problem — Strict Mode double-fire exists
// to surface missing cleanup, not to be silenced
function UserGreeting({ userId }) {
  const hasRun = useRef(false);
  useEffect(() => {
    if (hasRun.current) return;
    hasRun.current = true;
    showWelcomeToast(userId);
  }, [userId]);
}

// GOOD: if it's truly one-time mount setup
function UserGreeting({ userId }) {
  useMountEffect(() => {
    showWelcomeToast(userId);
  });
}

// BETTER: if the toast is a response to navigation, it belongs in the
// navigation handler, not in the component lifecycle at all
```

### `isMounted` ref to avoid set-state-after-unmount

```tsx
// BAD: isMounted ref masks a missing cancellation
function Profile({ userId }) {
  const [user, setUser] = useState(null);
  const isMounted = useRef(true);
  useEffect(() => {
    fetchUser(userId).then(data => {
      if (isMounted.current) setUser(data);
    });
    return () => { isMounted.current = false; };
  }, [userId]);
}

// GOOD: data-fetching library handles cancellation
function Profile({ userId }) {
  const { data: user } = useQuery(['user', userId], () => fetchUser(userId));
}

// GOOD: if no library, use a cleanup boolean in a custom hook (not a ref)
function useData(url) {
  const [data, setData] = useState(null);
  useEffect(() => {
    let ignore = false;
    fetch(url)
      .then(r => r.json())
      .then(json => { if (!ignore) setData(json); });
    return () => { ignore = true; };
  }, [url]);
  return data;
}
```

**Why `ignore` is not the same as `isMounted.current`:** The `ignore` boolean is scoped to a single effect execution and cleaned up by that same execution's cleanup function. It doesn't persist across renders or leak into other parts of the component. A `useRef` persists across the entire component lifetime and creates a second, invisible state channel.

### Ref to capture latest callback (dodging the dependency array)

```tsx
// BAD: ref stores latest callback to avoid listing it as a dependency
function ChatRoom({ roomId, onMessage }) {
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;

  useEffect(() => {
    const conn = createConnection(roomId);
    conn.on('message', (msg) => onMessageRef.current(msg));
    return () => conn.disconnect();
  }, [roomId]); // onMessage is missing — linter would complain without the ref trick
}

// GOOD: useEffectEvent (see section below)
// GOOD: if no useEffectEvent, isolate in a custom hook — never in a component
```

---

## useEffectEvent

`useEffectEvent` (stable since React 19.2) solves the "latest value in an effect" problem. It wraps non-reactive logic so that it always reads the latest values without being a dependency of the effect. Call the function it returns only from inside effects, never during render, and don't pass it to other components.

### Reading latest callback without refs

```tsx
// BAD: ref workaround for latest callback
function ChatRoom({ roomId, onMessage }) {
  const onMessageRef = useRef(onMessage);
  onMessageRef.current = onMessage;
  useEffect(() => {
    const conn = createConnection(roomId);
    conn.on('message', (msg) => onMessageRef.current(msg));
    return () => conn.disconnect();
  }, [roomId]);
}

// GOOD: useEffectEvent captures latest values; the effect lives in a named hook
function useChatConnection(roomId, onMessage) {
  const onMsg = useEffectEvent((msg) => {
    onMessage(msg);
  });

  useEffect(() => {
    const conn = createConnection(roomId);
    conn.on('message', onMsg);
    return () => conn.disconnect();
  }, [roomId]); // onMsg is stable, no need to list it
}

function ChatRoom({ roomId, onMessage }) {
  useChatConnection(roomId, onMessage);
  // ...
}
```

### Logging with latest state

```tsx
// BAD: ref to read latest theme in effect
function Page({ url }) {
  const [theme, setTheme] = useState('light');
  const themeRef = useRef(theme);
  themeRef.current = theme;
  useEffect(() => {
    logVisit(url, themeRef.current);
  }, [url]); // eslint-disable-next-line — lying to the linter

  // ...
}

// GOOD: useEffectEvent inside a named hook
function usePageVisitLog(url, theme) {
  const onVisit = useEffectEvent(() => {
    logVisit(url, theme); // always reads latest theme
  });
  useEffect(() => {
    onVisit();
  }, [url]);
}

function Page({ url }) {
  const [theme, setTheme] = useState('light');
  usePageVisitLog(url, theme);

  // ...
}
```

**Before React 19.2** (no `useEffectEvent`): prefer moving logic to event handlers or `useMountEffect`. If neither fits, isolate the ref workaround in a custom hook — never directly in a component.

---

## Callback Refs

When you need a side effect tied to a DOM node's presence, a callback ref is more reliable than `useRef` + `useMountEffect`. It fires exactly when the node attaches or detaches, with no timing issues.

### Measuring a DOM node

```tsx
// BAD: ref.current may be null on first render if the node is conditionally rendered
function MeasuredBox() {
  const ref = useRef<HTMLDivElement>(null);
  const [height, setHeight] = useState(0);
  useMountEffect(() => {
    setHeight(ref.current!.getBoundingClientRect().height);
  });
  return <div ref={ref}>Content</div>;
}

// GOOD: callback ref fires when node is attached
function MeasuredBox() {
  const [height, setHeight] = useState(0);
  const measuredRef = useCallback((node: HTMLDivElement | null) => {
    if (node !== null) {
      setHeight(node.getBoundingClientRect().height);
    }
  }, []);
  return <div ref={measuredRef}>Content</div>;
}
```

### Focus on mount

```tsx
// BAD
const inputRef = useRef<HTMLInputElement>(null);
useMountEffect(() => { inputRef.current?.focus(); });
return <input ref={inputRef} />;

// GOOD: callback ref
<input ref={(node) => node?.focus()} />
```

### Third-party library initialization (React 19+)

```tsx
// BAD: ref + useMountEffect
const containerRef = useRef<HTMLDivElement>(null);
useMountEffect(() => {
  const chart = new Chart(containerRef.current!, config);
  return () => chart.destroy();
});
return <div ref={containerRef} />;

// GOOD: callback ref with cleanup (React 19+ supports return values)
const chartRef = useCallback((node: HTMLDivElement | null) => {
  if (node === null) return;
  const chart = new Chart(node, config);
  return () => chart.destroy(); // cleanup when node detaches
}, [config]);
return <div ref={chartRef} />;
```

**Note:** React 19 supports cleanup return values from callback refs. For earlier versions, store the cleanup in a ref inside a custom hook.

### Callback refs and React Compiler

The `useCallback` wrappers above are for projects without React Compiler. A callback ref with a new identity on every render makes React detach and re-attach it, running its cleanup each time, so it has to be memoized. With React Compiler, write a plain function and let the compiler keep it stable:

```tsx
// GOOD (React Compiler)
const chartRef = (node: HTMLDivElement | null) => {
  if (node === null) return;
  const chart = new Chart(node, config);
  return () => chart.destroy();
};
return <div ref={chartRef} />;
```
