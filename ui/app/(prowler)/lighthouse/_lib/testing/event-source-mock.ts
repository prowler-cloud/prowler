import { vi } from "vitest";

// Controllable EventSource mock: records each instance so tests can drive
// named SSE events and connection failures, while still being a vi.fn so
// `expect(EventSource).toHaveBeenCalledWith(...)` keeps working.
export interface MockEventSource {
  url: string;
  readyState: number;
  onerror: ((event: Event) => void) | null;
  listeners: Map<string, Set<EventListener>>;
  addEventListener: (type: string, cb: EventListener) => void;
  close: ReturnType<typeof vi.fn>;
  emit: (type: string, data: unknown) => void;
  fail: (readyState: number) => void;
}

// The mock never fires "open": the client must POST the message without
// waiting for it (the backend sends no bytes until the worker emits, which
// only happens after the POST). This is the regression guard for the
// open-gate deadlock.
export function stubEventSource(): MockEventSource[] {
  const eventSources: MockEventSource[] = [];
  const EventSourceMock = vi.fn(function (this: MockEventSource, url: string) {
    this.url = url;
    this.readyState = 0;
    this.onerror = null;
    this.listeners = new Map();
    this.addEventListener = (type: string, cb: EventListener) => {
      const set = this.listeners.get(type) ?? new Set<EventListener>();
      set.add(cb);
      this.listeners.set(type, set);
    };
    this.close = vi.fn(() => {
      this.readyState = 2;
    });
    this.emit = (type: string, data: unknown) => {
      const event = new MessageEvent(type, { data: JSON.stringify(data) });
      this.listeners.get(type)?.forEach((cb) => cb(event));
    };
    this.fail = (readyState: number) => {
      this.readyState = readyState;
      this.onerror?.(new Event("error"));
    };
    eventSources.push(this);
  });
  Object.assign(EventSourceMock, { CONNECTING: 0, OPEN: 1, CLOSED: 2 });
  vi.stubGlobal("EventSource", EventSourceMock);
  return eventSources;
}
