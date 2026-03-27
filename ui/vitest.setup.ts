import "@testing-library/jest-dom/vitest";

const isBrowserMode =
  typeof globalThis !== "undefined" &&
  "__vitest_browser__" in globalThis &&
  (globalThis as Record<string, unknown>).__vitest_browser__ === true;

if (isBrowserMode) {
  // Disable CSS animations to prevent race conditions with Radix/tailwindcss-animate.
  // Without this, toBeVisible() can race against data-[state=open]:animate-in.
  const style = document.createElement("style");
  style.textContent = `
    *, *::before, *::after {
      animation-duration: 0s !important;
      animation-delay: 0s !important;
      transition-duration: 0s !important;
      transition-delay: 0s !important;
    }
  `;
  document.head.appendChild(style);
}

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
