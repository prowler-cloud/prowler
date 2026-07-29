"use client";

import { Bot, Loader2, Save } from "lucide-react";
import { useState } from "react";

import { updateLighthouseV2Configuration } from "@/app/(prowler)/lighthouse/_actions";
import { BUSINESS_CONTEXT_LIMIT } from "@/app/(prowler)/lighthouse/_lib/config";
import { Button } from "@/components/shadcn/button/button";
import { Card } from "@/components/shadcn/card/card";
import { Field, FieldError, FieldLabel } from "@/components/shadcn/field/field";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { cn } from "@/lib/utils";

// Shared business context. The backend syncs it across every provider config, so
// it is edited once here against any single configuration rather than per provider.
export function LighthouseV2BusinessContextForm({
  configurationId,
  initialBusinessContext,
}: {
  configurationId: string;
  initialBusinessContext: string;
}) {
  const [businessContext, setBusinessContext] = useState(
    initialBusinessContext,
  );
  const [savedContext, setSavedContext] = useState(initialBusinessContext);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const overLimit = businessContext.length > BUSINESS_CONTEXT_LIMIT;
  const isDirty = businessContext !== savedContext;
  const canSave = isDirty && !overLimit && !saving;

  const handleSave = async () => {
    if (!canSave) return;

    setSaving(true);
    setError(null);

    try {
      const result = await updateLighthouseV2Configuration(configurationId, {
        businessContext,
      });

      if ("error" in result) {
        setError(result.error);
        return;
      }

      setSavedContext(result.data.businessContext);
      setBusinessContext(result.data.businessContext);
    } catch {
      setError("Something went wrong while saving. Please try again.");
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card
      variant="inner"
      padding="none"
      data-lighthouse-v2-business-context=""
      className="gap-4 p-4 md:p-5"
    >
      <div className="flex items-start gap-3">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex size-12 shrink-0 items-center justify-center rounded-[10px] border">
          <Bot className="text-text-neutral-secondary size-6" />
        </div>
        <div className="min-w-0">
          <h3 className="text-text-neutral-primary text-xl font-semibold">
            Business context
          </h3>
          <p className="text-text-neutral-secondary mt-1 max-w-2xl text-sm">
            Shared context Lighthouse AI considers for every provider and chat.
          </p>
        </div>
      </div>

      <div className="flex flex-col gap-4">
        <Field>
          <div className="flex items-center justify-between gap-3">
            <FieldLabel htmlFor="lighthouse-v2-business-context">
              Business context
            </FieldLabel>
            <span
              className={cn(
                "text-xs",
                overLimit
                  ? "text-text-error-primary"
                  : "text-text-neutral-tertiary",
              )}
            >
              {businessContext.length}/{BUSINESS_CONTEXT_LIMIT}
            </span>
          </div>
          <Textarea
            id="lighthouse-v2-business-context"
            textareaSize="lg"
            aria-invalid={overLimit}
            value={businessContext}
            onChange={(event) => setBusinessContext(event.target.value)}
            placeholder="Example: production AWS accounts, PCI workloads, EU data residency, critical internet-facing services..."
          />
          {overLimit && (
            <FieldError>
              Business context cannot exceed {BUSINESS_CONTEXT_LIMIT}{" "}
              characters.
            </FieldError>
          )}
          {error && <FieldError>{error}</FieldError>}
        </Field>

        <div className="flex justify-end">
          <Button
            type="button"
            aria-label="Save business context"
            onClick={handleSave}
            disabled={!canSave}
          >
            {saving ? <Loader2 className="animate-spin" /> : <Save />}
            {saving ? "Saving…" : "Save"}
          </Button>
        </div>
      </div>
    </Card>
  );
}
