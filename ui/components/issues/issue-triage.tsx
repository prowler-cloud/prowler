"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

import {
  addIssueNote,
  getIssueNotes,
  updateIssueTriage,
} from "@/actions/issues";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { Button } from "@/components/shadcn/button/button";
import { DateWithTime } from "@/components/shadcn/entities";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { useToast } from "@/components/shadcn/toast/use-toast";
import { TriageStatusPicker } from "@/components/shared/triage/triage-status-picker";
import { usageLimitToastAction } from "@/components/shared/usage-limit-message";
import { isUsageLimitError } from "@/lib/action-errors";
import {
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  isManualStatus,
} from "@/types/findings-triage";
import { IssueTriageNote } from "@/types/issues";

import type { IssueTriageProps } from "./types";

/**
 * The decision on the path, and why.
 *
 * It belongs to the account and the pattern, not to this scan's row, so it
 * still applies after the next scan. The verdict beside it is the engine's:
 * accepting a risk does not make a path unexploitable.
 */
export const IssueTriage = ({ id, status }: IssueTriageProps) => {
  const router = useRouter();
  const { toast } = useToast();
  const [pending, startTransition] = useTransition();
  const [nextStatus, setNextStatus] = useState(status);
  const [shownStatus, setShownStatus] = useState(status);
  const [note, setNote] = useState("");
  const [notes, setNotes] = useState<IssueTriageNote[] | undefined>([]);
  const [reload, setReload] = useState(0);

  // Follow the status the server now reports (a refresh after a save, or
  // someone else's decision), so a note-only save never writes back a stale one.
  if (status !== shownStatus) {
    setShownStatus(status);
    setNextStatus(status);
  }

  useEffect(() => {
    let cancelled = false;
    getIssueNotes(id).then((loaded) => {
      if (!cancelled) setNotes(loaded);
    });
    return () => {
      cancelled = true;
    };
  }, [id, reload]);

  const statusChanged = nextStatus !== status;
  const trimmedNote = note.trim();

  const save = () =>
    startTransition(async () => {
      const result =
        statusChanged && isManualStatus(nextStatus)
          ? await updateIssueTriage(id, {
              status: nextStatus,
              note: trimmedNote || undefined,
            })
          : await addIssueNote(id, trimmedNote);

      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Triage not saved",
          description: result.error,
          ...(isUsageLimitError(result) && { action: usageLimitToastAction() }),
        });
        return;
      }
      setNote("");
      setReload((value) => value + 1);
      router.refresh();
    });

  return (
    <section aria-label="Triage" className="flex flex-col gap-3">
      <h4 className="text-sm font-semibold">Triage</h4>
      <div className="flex flex-wrap items-center gap-2">
        <div className="w-40">
          <TriageStatusPicker
            disabled={pending}
            value={nextStatus}
            statusValues={FINDING_TRIAGE_MANUAL_STATUS_VALUES}
            onValueChange={setNextStatus}
          />
        </div>
        <Button
          size="sm"
          onClick={save}
          disabled={pending || (!statusChanged && !trimmedNote)}
        >
          {pending ? "Saving…" : "Save triage"}
        </Button>
      </div>
      <Textarea
        aria-label="Triage note"
        placeholder="Why this decision? The next person to read this issue only has what you write here."
        value={note}
        maxLength={FINDING_TRIAGE_NOTE_MAX_LENGTH}
        rows={3}
        // A successful save clears the note: text typed meanwhile would be lost.
        disabled={pending}
        onChange={(event) => setNote(event.target.value)}
      />
      {notes === undefined ? (
        <IssuesLoadError
          message="Could not load the notes for this issue."
          onRetry={() => setReload((value) => value + 1)}
        />
      ) : notes.length > 0 ? (
        <ul className="flex flex-col gap-2">
          {notes.map((item) => (
            <li key={item.id} className="flex flex-col gap-1">
              <p className="text-text-neutral-secondary text-sm whitespace-pre-wrap">
                {item.body}
              </p>
              <div className="text-text-neutral-tertiary flex items-center gap-2 text-xs">
                <span>{item.author ?? "Unknown"}</span>
                <DateWithTime inline dateTime={item.insertedAt} />
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
};
