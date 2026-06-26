import { AlertCircle, DatabaseZap } from "lucide-react";

import { Alert, AlertDescription, AlertTitle } from "@/components/shadcn/alert";
import { Card, CardContent } from "@/components/shadcn/card/card";

export function LighthouseV2EmptyState({ error }: { error?: string }) {
  return (
    <Card variant="base" padding="lg" className="mx-auto max-w-3xl">
      <CardContent className="flex flex-col items-center gap-4 py-8 text-center">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-14 items-center justify-center rounded-[14px] border">
          <DatabaseZap className="text-text-neutral-secondary size-7" />
        </div>
        <div>
          <h2 className="text-text-neutral-primary text-xl font-semibold">
            No Lighthouse AI providers available
          </h2>
          <p className="text-text-neutral-secondary mt-2 text-sm">
            Cloud did not return supported providers for Lighthouse AI
            configuration.
          </p>
        </div>
        {error && (
          <Alert variant="error" className="text-left">
            <AlertCircle className="size-4" />
            <AlertTitle>Configuration unavailable</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </CardContent>
    </Card>
  );
}
