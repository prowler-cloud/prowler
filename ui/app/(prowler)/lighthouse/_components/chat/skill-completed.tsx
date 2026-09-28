"use client";

import { ArrowRight, BrainIcon } from "lucide-react";
import dynamic from "next/dynamic";
import { useState } from "react";

import type { SkillRunInfo } from "@/app/(prowler)/lighthouse/_lib/messages";
import {
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Part,
} from "@/app/(prowler)/lighthouse/_types";
import { Badge } from "@/components/shadcn/badge/badge";
import { Button } from "@/components/shadcn/button/button";
import { getNextSkill } from "@/lib/lighthouse/skills/registry";
import {
  JIRA_DISPATCH_TARGET,
  JIRA_TARGET_SELECTION_KIND,
} from "@/types/integrations";
import { LIGHTHOUSE_CONTEXT_KIND } from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Lazy-loaded: the Jira/Mute machinery (and its server-action imports) only
// loads when the user actually opens one of these from a finished skill run.
// `loading` gives each modal its own Suspense boundary — without it the lazy
// load suspends up to the chat panel's boundary and swaps the whole
// conversation for its skeleton fallback while the chunk downloads.
const SendToJiraModal = dynamic(
  () =>
    import("@/components/findings/send-to-jira-modal").then(
      (module) => module.SendToJiraModal,
    ),
  { loading: () => null },
);
const MuteFindingsModal = dynamic(
  () =>
    import("@/components/findings/mute-findings-modal").then(
      (module) => module.MuteFindingsModal,
    ),
  { loading: () => null },
);

// One-line receipt of a finished run (design 1j): "Ran <skill> · tools ·
// time". Static on purpose — the full trace (narration and tool calls, in
// order) lives in the message body, so the receipt never duplicates it. The
// summary reports only observed activity — never the catalog's step plan.
export function SkillRunReceipt({
  skillRun,
  parts,
  completedAt,
}: {
  skillRun: SkillRunInfo;
  parts: LighthouseV2Part[];
  completedAt: string;
}) {
  const toolParts = parts.filter(
    (part) => part.type === LIGHTHOUSE_V2_PART_TYPE.TOOL_CALL,
  );
  const summary = [
    `${toolParts.length} ${toolParts.length === 1 ? "tool" : "tools"}`,
    formatRunDuration(skillRun.launchedAt, completedAt),
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="text-text-neutral-secondary flex items-center gap-2 text-xs">
      <BrainIcon className="size-4" />
      <span>
        Ran{" "}
        <span className="text-text-neutral-primary font-medium">
          {skillRun.ref.name}
        </span>
        {summary && ` · ${summary}`}
      </span>
    </div>
  );
}

// Action row under the answer (design 1j): copy, dispatch to Jira, mute the
// finding, and the suggested follow-up skill.
export function SkillActionsRow({
  skillRun,
  onLaunchSkill,
}: {
  skillRun: SkillRunInfo;
  onLaunchSkill?: (skill: LighthouseSkillDefinition) => void;
}) {
  const [isJiraOpen, setIsJiraOpen] = useState(false);
  const [isMuteOpen, setIsMuteOpen] = useState(false);
  const finding = skillRun.context?.items.find(
    (item) => item.kind === LIGHTHOUSE_CONTEXT_KIND.FINDING,
  );
  const findingId =
    finding?.kind === LIGHTHOUSE_CONTEXT_KIND.FINDING
      ? finding.findingId
      : undefined;
  const nextSkill = getNextSkill(skillRun.ref.skillId);

  return (
    <div className="flex flex-wrap items-center gap-2">
      {findingId && (
        <>
          <Button
            type="button"
            variant="outline"
            size="xs"
            onClick={() => setIsJiraOpen(true)}
          >
            Create Jira ticket
          </Button>
          <Button
            type="button"
            variant="outline"
            size="xs"
            onClick={() => setIsMuteOpen(true)}
          >
            Mute finding
          </Button>
          {isJiraOpen && (
            <SendToJiraModal
              isOpen={isJiraOpen}
              onOpenChange={setIsJiraOpen}
              selection={{
                kind: JIRA_TARGET_SELECTION_KIND.SINGLE,
                targetId: findingId,
                targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
              }}
              findingTitle={finding?.label}
            />
          )}
          {isMuteOpen && (
            <MuteFindingsModal
              isOpen={isMuteOpen}
              onOpenChange={setIsMuteOpen}
              findingIds={[findingId]}
            />
          )}
        </>
      )}
      {nextSkill && onLaunchSkill && (
        <Badge variant="lighthouse" asChild>
          <button
            type="button"
            className="cursor-pointer"
            onClick={() => onLaunchSkill(nextSkill)}
          >
            <nextSkill.icon aria-hidden />
            Next: {nextSkill.name}
            <ArrowRight aria-hidden />
          </button>
        </Badge>
      )}
    </div>
  );
}

function formatRunDuration(
  launchedAt: string,
  completedAt: string,
): string | null {
  const started = new Date(launchedAt).getTime();
  const finished = new Date(completedAt).getTime();
  if (Number.isNaN(started) || Number.isNaN(finished) || finished < started) {
    return null;
  }
  const totalSeconds = Math.round((finished - started) / 1000);
  if (totalSeconds < 60) return `${totalSeconds}s`;
  const minutes = Math.floor(totalSeconds / 60);
  return `${minutes}m ${totalSeconds % 60}s`;
}
