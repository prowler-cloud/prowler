import type { ComponentType, PropsWithChildren, ReactElement } from "react";
import { render as vitestRender } from "vitest-browser-react";

const TestProviders = ({ children }: PropsWithChildren) => <>{children}</>;

type RenderOptions = Parameters<typeof vitestRender>[1];

export function render(ui: ReactElement, options?: RenderOptions) {
  const userWrapper = options?.wrapper as
    | ComponentType<PropsWithChildren>
    | undefined;

  const Wrapper = userWrapper
    ? ({ children }: PropsWithChildren) => {
        const Inner = userWrapper;
        return (
          <TestProviders>
            <Inner>{children}</Inner>
          </TestProviders>
        );
      }
    : TestProviders;

  return vitestRender(ui, { ...options, wrapper: Wrapper });
}
