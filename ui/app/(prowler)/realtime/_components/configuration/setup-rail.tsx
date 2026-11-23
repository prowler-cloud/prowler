"use client";

import { useRouter } from "next/navigation";

import { LIGHTHOUSE_CHAT_PATH } from "@/app/(prowler)/realtime/_lib/routes";
import {
  CONFIG_SECTION_LABELS,
  CONFIG_SECTION_ORDER,
  type ConfigSection,
  isStepRequired,
  requiredProgress,
  STEP_STATE,
  type StepState,
  stepState,
} from "@/app/(prowler)/realtime/_lib/setup";
import type { RealtimeSetupPayload } from "@/app/(prowler)/realtime/_types";
import { Button, Card, Progress } from "@/components/shadcn";
import {
  LighthouseCallout,
  LighthouseCalloutAction,
  LighthouseCalloutActions,
  LighthouseCalloutBody,
  LighthouseCalloutDescription,
  LighthouseCalloutIcon,
  LIGHTHOUSE_CALLOUT_LAYOUT,
  LighthouseCalloutTitle,
} from "@/components/shadcn/lighthouse-callout";
import { cn } from "@/lib/utils";

const DOT_STYLES: Record<StepState, string> = {
  [STEP_STATE.DONE]: "bg-bg-pass",
  [STEP_STATE.CURRENT]: "bg-button-primary ring-button-primary/30 ring-2",
  [STEP_STATE.TODO]: "bg-border-neutral-tertiary",
};

const STATE_LABELS: Record<StepState, string> = {
  [STEP_STATE.DONE]: "done",
  [STEP_STATE.CURRENT]: "next",
  [STEP_STATE.TODO]: "to do",
};

interface SetupRailProps {
  setup: RealtimeSetupPayload | null;
  onOpenSection: (section: ConfigSection) => void;
}

/** Setup progress from the API's checklist, plus the Lighthouse AI way. */
export function SetupRail({ setup, onOpenSection }: SetupRailProps) {
  const router = useRouter();
  const progress = requiredProgress(setup);
  const percent = progress.total
    ? Math.round((progress.done / progress.total) * 100)
    : 0;

  return (
    <aside aria-label="Setup progress" className="flex flex-col gap-4">
      <Card variant="base" className="gap-3">
        <h2 className="text-text-neutral-primary text-sm font-semibold">
          {setup?.activated ? "Setup complete" : "Set up Realtime"}
        </h2>
        <div className="flex items-center justify-between text-xs">
          <span className="text-text-neutral-tertiary">Required steps</span>
          <span className="text-text-neutral-primary font-semibold">
            {progress.done} of {progress.total}
          </span>
        </div>
        <Progress value={percent} aria-label="Required steps done" />
        <ol className="border-border-neutral-secondary flex flex-col border-t pt-1">
          {CONFIG_SECTION_ORDER.map((section) => {
            const state = stepState(setup, section);
            const optional = setup ? !isStepRequired(setup, section) : false;
            return (
              <li key={section}>
                <Button
                  variant="ghost"
                  size="sm"
                  className={cn(
                    "w-full justify-start gap-2.5 px-2",
                    state === STEP_STATE.CURRENT && "font-semibold",
                  )}
                  onClick={() => onOpenSection(section)}
                >
                  <span
                    aria-hidden
                    className={cn(
                      "size-2 shrink-0 rounded-full",
                      DOT_STYLES[state],
                    )}
                  />
                  <span className="truncate">
                    {CONFIG_SECTION_LABELS[section]}
                    {optional && (
                      <span className="text-text-neutral-tertiary font-normal">
                        {" "}
                        · optional
                      </span>
                    )}
                  </span>
                  <span className="sr-only">({STATE_LABELS[state]})</span>
                </Button>
              </li>
            );
          })}
        </ol>
      </Card>
      <LighthouseCallout layout={LIGHTHOUSE_CALLOUT_LAYOUT.SIDEBAR}>
        <LighthouseCalloutIcon />
        <LighthouseCalloutBody>
          <LighthouseCalloutTitle>
            Prefer to do this by chat?
          </LighthouseCalloutTitle>
          <LighthouseCalloutDescription>
            Lighthouse AI can set up Realtime with you, step by step.
          </LighthouseCalloutDescription>
        </LighthouseCalloutBody>
        <LighthouseCalloutActions>
          <LighthouseCalloutAction
            onClick={() => router.push(LIGHTHOUSE_CHAT_PATH)}
          >
            Ask Lighthouse AI
          </LighthouseCalloutAction>
        </LighthouseCalloutActions>
      </LighthouseCallout>
    </aside>
  );
}
