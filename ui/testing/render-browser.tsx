import { SessionProvider } from "next-auth/react";
import type { ReactElement, ReactNode } from "react";
import {
  render as vitestRender,
  type RenderOptions,
} from "vitest-browser-react";

function TestProviders({ children }: { children: ReactNode }) {
  return <SessionProvider>{children}</SessionProvider>;
}

export function renderBrowser(ui: ReactElement, options?: RenderOptions) {
  return vitestRender(ui, { wrapper: TestProviders, ...options });
}
