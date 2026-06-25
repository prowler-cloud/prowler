import { CheckCircle2, CircleDashed } from "lucide-react";

import { formatTokenLimit } from "@/app/(prowler)/lighthouse/_lib/format";
import { type LighthouseV2SupportedModel } from "@/app/(prowler)/lighthouse/_types";

export function ModelDetails({
  model,
}: {
  model?: LighthouseV2SupportedModel;
}) {
  if (!model) {
    return (
      <div className="border-border-neutral-secondary bg-bg-neutral-tertiary mt-3 rounded-[10px] border px-3 py-3">
        <p className="text-text-neutral-secondary text-sm">
          Select a model to see capabilities.
        </p>
      </div>
    );
  }

  return (
    <div className="border-border-neutral-secondary bg-bg-neutral-tertiary mt-3 grid gap-3 rounded-[10px] border px-3 py-3 sm:grid-cols-3">
      <CapabilityItem label="Tools" enabled={model.supportsFunctionCalling} />
      <CapabilityItem label="Vision" enabled={model.supportsVision} />
      <CapabilityItem label="Reasoning" enabled={model.supportsReasoning} />
      <div className="text-text-neutral-secondary text-xs sm:col-span-3">
        Input tokens: {formatTokenLimit(model.maxInputTokens)} · Output tokens:{" "}
        {formatTokenLimit(model.maxOutputTokens)}
      </div>
    </div>
  );
}

function CapabilityItem({
  enabled,
  label,
}: {
  enabled: boolean | null;
  label: string;
}) {
  return (
    <div className="flex items-center gap-2 text-sm">
      {enabled ? (
        <CheckCircle2 className="text-text-success-primary size-4" />
      ) : (
        <CircleDashed className="text-text-neutral-tertiary size-4" />
      )}
      <span className="text-text-neutral-primary">{label}</span>
    </div>
  );
}
