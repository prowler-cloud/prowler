"use client";

import { CheckCircle2 } from "lucide-react";

export function LaunchStep() {
  return (
    <div className="flex min-h-[320px] flex-col items-center justify-center gap-4 text-center">
      <CheckCircle2 className="text-success size-12" />
      <h3 className="text-xl font-semibold">Provider connected successfully</h3>
      <p className="text-muted-foreground text-sm">
        Continue with the action button to go to scans.
      </p>
    </div>
  );
}
