"use client";

import { Component, type ReactNode } from "react";

import { Button } from "@/components/shadcn/button/button";

interface SidePanelErrorBoundaryProps {
  children: ReactNode;
  onRetry: () => void;
}

interface SidePanelErrorBoundaryState {
  hasError: boolean;
}

// GlobalSidePanel mounts at the app-layout level, above every segment
// error.tsx, so an uncaught render/chunk-load error in a lazy tab would
// bubble to global-error and replace the whole app. Class component because
// React has no hook equivalent for error boundaries.
export class SidePanelErrorBoundary extends Component<
  SidePanelErrorBoundaryProps,
  SidePanelErrorBoundaryState
> {
  state: SidePanelErrorBoundaryState = { hasError: false };

  static getDerivedStateFromError(): SidePanelErrorBoundaryState {
    return { hasError: true };
  }

  private handleRetry = () => {
    this.props.onRetry();
    this.setState({ hasError: false });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center">
          <p className="text-text-neutral-primary text-sm font-medium">
            This panel failed to load.
          </p>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={this.handleRetry}
          >
            Retry
          </Button>
        </div>
      );
    }
    return this.props.children;
  }
}
