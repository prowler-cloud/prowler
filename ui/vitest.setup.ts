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
