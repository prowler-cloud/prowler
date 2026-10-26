"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";

import {
  addIssueNote,
  getIssueNotes,
  updateIssueTriage,
} from "@/actions/issues";
import { TRIAGE_STATUS_TEXT_CLASS } from "@/components/findings/table/finding-triage-status-control";
import { Button } from "@/components/shadcn/button/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
} from "@/components/shadcn/select/select";
import { Textarea } from "@/components/shadcn/textarea/textarea";
import { useToast } from "@/components/shadcn/toast/use-toast";
import { cn } from "@/lib/utils";
import {
  FINDING_TRIAGE_MANUAL_STATUS_VALUES,
  FINDING_TRIAGE_NOTE_MAX_LENGTH,
  FINDING_TRIAGE_STATUS_LABELS,
  type FindingTriageManualStatus,
  type FindingTriageStatus,
} from "@/types/findings-triage";
import { IssueTriageNote } from "@/types/issues";

interface IssueTriageProps {
  id: string;
  status: FindingTriageStatus;
}

const isManualStatus = (
  status: FindingTriageStatus,
): status is FindingTriageManualStatus =>
  (FINDING_TRIAGE_MANUAL_STATUS_VALUES as readonly string[]).includes(status);

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
  const [note, setNote] = useState("");
  const [notes, setNotes] = useState<IssueTriageNote[] | undefined>([]);
  const [reload, setReload] = useState(0);

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
          <Select
            value={nextStatus}
            onValueChange={(value) =>
              setNextStatus(value as FindingTriageStatus)
            }
          >
            <SelectTrigger aria-label="Triage status" size="sm" iconSize="sm">
              <span
                className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[nextStatus])}
              >
                {FINDING_TRIAGE_STATUS_LABELS[nextStatus]}
              </span>
            </SelectTrigger>
            <SelectContent>
              {FINDING_TRIAGE_MANUAL_STATUS_VALUES.map((value) => (
                <SelectItem
                  key={value}
                  value={value}
                  aria-label={FINDING_TRIAGE_STATUS_LABELS[value]}
                >
                  <span
                    className={cn("truncate", TRIAGE_STATUS_TEXT_CLASS[value])}
                  >
                    {FINDING_TRIAGE_STATUS_LABELS[value]}
                  </span>
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
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
        onChange={(event) => setNote(event.target.value)}
      />
      {notes === undefined ? (
        <p role="alert" className="text-text-neutral-tertiary text-sm">
          Could not load the notes for this issue.
        </p>
      ) : notes.length > 0 ? (
        <ul className="flex flex-col gap-2">
          {notes.map((item) => (
            <li key={item.id} className="flex flex-col gap-1">
              <p className="text-text-neutral-secondary text-sm whitespace-pre-wrap">
                {item.body}
              </p>
              <span className="text-text-neutral-tertiary text-xs">
                {item.author ?? "Unknown"} ·{" "}
                {new Date(item.insertedAt).toLocaleString()}
              </span>
            </li>
          ))}
        </ul>
      ) : null}
    </section>
  );
};
