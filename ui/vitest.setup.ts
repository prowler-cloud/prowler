import "@testing-library/jest-dom/vitest";

import { vi } from "vitest";

// `next/font/google` is a build-time transform handled by Next's compiler; under
// Vitest the loaders are plain functions that aren't transformed, so calling
// them throws. Stub them with the shape the app reads (`className`/`variable`)
// so any component importing `@/config/fonts` (e.g. the DS Textarea) can render.
vi.mock("next/font/google", () => ({
  Inter: () => ({ className: "font-sans", variable: "--font-sans", style: {} }),
  Fira_Code: () => ({
    className: "font-mono",
    variable: "--font-mono",
    style: {},
  }),
}));

class MockStorage implements Storage {
  private readonly store = new Map<string, string>();

  get length() {
    return this.store.size;
  }

  clear() {
    this.store.clear();
  }

  getItem(key: string) {
    return this.store.get(key) ?? null;
  }

  key(index: number) {
    return Array.from(this.store.keys())[index] ?? null;
  }

  removeItem(key: string) {
    this.store.delete(key);
  }

  setItem(key: string, value: string) {
    this.store.set(key, value);
  }
}

const localStorageMock = new MockStorage();
const sessionStorageMock = new MockStorage();

Object.defineProperty(globalThis, "localStorage", {
  value: localStorageMock,
  configurable: true,
});

Object.defineProperty(window, "localStorage", {
  value: localStorageMock,
  configurable: true,
});

Object.defineProperty(globalThis, "sessionStorage", {
  value: sessionStorageMock,
  configurable: true,
});

Object.defineProperty(window, "sessionStorage", {
  value: sessionStorageMock,
  configurable: true,
});

const emptyClientRects = [] as unknown as DOMRectList;
const emptyRect = {
  x: 0,
  y: 0,
  width: 0,
  height: 0,
  top: 0,
  right: 0,
  bottom: 0,
  left: 0,
  toJSON: () => ({}),
} as DOMRect;

if (!Range.prototype.getClientRects) {
  Range.prototype.getClientRects = () => emptyClientRects;
}

if (!Range.prototype.getBoundingClientRect) {
  Range.prototype.getBoundingClientRect = () => emptyRect;
}
