"use client";

import { Modal } from "@/components/shadcn/modal";

import { MuteRuleTableData } from "./mute-rule-target-previews";

interface MuteRuleTargetsModalProps {
  muteRule: MuteRuleTableData | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function MuteRuleTargetsModal({
  muteRule,
  open,
  onOpenChange,
}: MuteRuleTargetsModalProps) {
  if (!muteRule) {
    return null;
  }

  const targetCount = muteRule.targetLabels.length;

  return (
    <Modal
      open={open}
      onOpenChange={onOpenChange}
      title="Muted Findings"
      description="Review every finding currently muted by this rule."
      size="xl"
    >
      <div className="flex flex-col gap-5">
        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary flex items-start justify-between gap-4 rounded-xl border p-4">
          <div className="min-w-0">
            <p className="text-text-neutral-tertiary text-xs font-medium tracking-[0.08em] uppercase">
              Mute rule
            </p>
            <p className="text-text-neutral-primary mt-2 truncate text-sm font-medium">
              {muteRule.attributes.name}
            </p>
            <p className="text-text-neutral-secondary mt-1 text-xs">
              This mute rule currently affects {targetCount}{" "}
              {targetCount === 1 ? "finding" : "findings"}.
            </p>
          </div>
          <div className="border-border-neutral-secondary bg-bg-neutral-secondary text-text-neutral-primary shrink-0 rounded-full border px-3 py-1 text-xs font-medium">
            {targetCount} {targetCount === 1 ? "finding" : "findings"}
          </div>
        </div>

        <div className="border-border-neutral-secondary bg-bg-neutral-tertiary max-h-[60vh] overflow-y-auto rounded-xl border">
          <ul className="divide-border-neutral-secondary divide-y">
            {muteRule.targetLabels.map((label, index) => {
              const [title, ...metaParts] = label.split(" • ");
              const meta = metaParts.join(" • ").trim();

              return (
                <li
                  key={`${muteRule.id}-${label}-${index}`}
                  className="px-4 py-3"
                >
                  <p className="text-text-neutral-primary text-sm font-medium">
                    {title}
                  </p>
                  {meta ? (
                    <p className="text-text-neutral-tertiary mt-1 text-xs">
                      {meta}
                    </p>
                  ) : null}
                </li>
              );
            })}
          </ul>
        </div>
      </div>
    </Modal>
  );
}
