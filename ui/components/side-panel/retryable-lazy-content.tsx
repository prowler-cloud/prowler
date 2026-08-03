"use client";

import {
  type ComponentType,
  lazy,
  type ReactNode,
  Suspense,
  useState,
} from "react";

import { SidePanelErrorBoundary } from "./side-panel-error-boundary";

interface RetryableLazyContentProps {
  load: () => Promise<{ default: ComponentType }>;
  fallback: ReactNode;
}

export function RetryableLazyContent({
  load,
  fallback,
}: RetryableLazyContentProps) {
  const [Content, setContent] = useState(() => lazy(load));

  const handleRetry = () => {
    setContent(lazy(load));
  };

  return (
    <SidePanelErrorBoundary onRetry={handleRetry}>
      <Suspense fallback={fallback}>
        <Content />
      </Suspense>
    </SidePanelErrorBoundary>
  );
}
