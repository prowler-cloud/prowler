import { vi } from "vitest";

// `next/font/google` is a build-time transform handled by Next's compiler; under
// Vitest the loaders are plain functions that aren't transformed, so calling
// them throws. Stub them with the shape the app reads (`className`/`variable`)
// so any component importing `@/config/fonts` (e.g. the DS Textarea) can render.
// Shared between vitest.setup.ts (jsdom) and vitest.browser.setup.ts (browser
// mode) so both projects cover it.
vi.mock("next/font/google", () => ({
  Inter: () => ({ className: "font-sans", variable: "--font-sans", style: {} }),
  Fira_Code: () => ({
    className: "font-mono",
    variable: "--font-mono",
    style: {},
  }),
}));
