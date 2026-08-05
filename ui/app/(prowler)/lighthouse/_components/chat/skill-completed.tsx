"use client";

import { ArrowRight, Check, Copy } from "lucide-react";
import dynamic from "next/dynamic";
import { useState } from "react";

import {
  ChainOfThought,
  ChainOfThoughtContent,
  ChainOfThoughtHeader,
} from "@/app/(prowler)/lighthouse/_components/ai-elements/chain-of-thought";
import type { SkillRunInfo } from "@/app/(prowler)/lighthouse/_lib/messages";
import {
  LIGHTHOUSE_V2_PART_TYPE,
  type LighthouseV2Part,
} from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import { getNextSkill, getSkillById } from "@/lib/lighthouse/skills/registry";
import {
  JIRA_DISPATCH_TARGET,
  JIRA_TARGET_SELECTION_KIND,
} from "@/types/integrations";
import { LIGHTHOUSE_CONTEXT_KIND } from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

import { ToolCalls } from "./tool-call-part";

// Lazy-loaded: the Jira/Mute machinery (and its server-action imports) only
// loads when the user actually opens one of these from a finished skill run.
const SendToJiraModal = dynamic(() =>
  import("@/components/findings/send-to-jira-modal").then(
    (module) => module.SendToJiraModal,
  ),
);
const MuteFindingsModal = dynamic(() =>
  import("@/components/findings/mute-findings-modal").then(
    (module) => module.MuteFindingsModal,
  ),
);

// One-line receipt of a finished run (design 1j): the chain of thought
// collapses to "Ran <skill> · steps · tools · time" with the trace behind it.
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
  const definition = getSkillById(skillRun.ref.skillId);
  const summary = [
    definition ? `${definition.steps.length} steps` : null,
    `${toolParts.length} ${toolParts.length === 1 ? "tool" : "tools"}`,
    formatRunDuration(skillRun.launchedAt, completedAt),
  ]
    .filter(Boolean)
    .join(" · ");

  return (
    <ChainOfThought className="space-y-0">
      <ChainOfThoughtHeader className="text-text-neutral-secondary text-xs">
        Ran{" "}
        <span className="text-text-neutral-primary font-medium">
          {skillRun.ref.name}
        </span>
        {summary && ` · ${summary}`}
      </ChainOfThoughtHeader>
      {toolParts.length > 0 && (
        <ChainOfThoughtContent>
          <ToolCalls parts={toolParts} />
        </ChainOfThoughtContent>
      )}
    </ChainOfThought>
  );
}

// Action row under the answer (design 1j): copy, dispatch to Jira, mute the
// finding, and the suggested follow-up skill.
export function SkillActionsRow({
  skillRun,
  messageText,
  onLaunchSkill,
}: {
  skillRun: SkillRunInfo;
  messageText: string;
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
      <CopyAnswerButton text={messageText} />
      {findingId && (
        <>
          <Button
            type="button"
            variant="outline"
            size="sm"
            onClick={() => setIsJiraOpen(true)}
          >
            Create Jira ticket
          </Button>
          <Button
            type="button"
            variant="outline"
            size="sm"
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
        <Button
          type="button"
          variant="outline"
          size="sm"
          onClick={() => onLaunchSkill(nextSkill)}
        >
          <nextSkill.icon className="text-text-success-primary size-3.5" />
          Next: {nextSkill.name}
          <ArrowRight className="size-3.5" />
        </Button>
      )}
    </div>
  );
}

function CopyAnswerButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard can reject (e.g. permissions); nothing to recover.
    }
  };

  return (
    <Button type="button" variant="outline" size="sm" onClick={handleCopy}>
      {copied ? <Check className="size-3.5" /> : <Copy className="size-3.5" />}
      Copy
    </Button>
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
