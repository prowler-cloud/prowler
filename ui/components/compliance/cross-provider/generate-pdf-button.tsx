"use client";

import { DownloadIcon, FileDown, Loader2 } from "lucide-react";
import type { ReactNode } from "react";
import { useCallback, useRef, useState } from "react";

import type { LatestCrossProviderPdfReport } from "@/actions/compliances";
import {
  generateCrossProviderCompliancePdf,
  getCrossProviderCompliancePdf,
} from "@/actions/compliances";
import { Button } from "@/components/shadcn/button/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/shadcn/dialog";
import { Input } from "@/components/shadcn/input/input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { toast } from "@/components/ui/toast";
import { downloadFile } from "@/lib/helper";
import { cn } from "@/lib/utils";
import { useCrossProviderPdfStore } from "@/store/cross-provider-pdf/store";

interface GeneratePdfButtonProps {
  /** e.g. "csa_ccm_4.0" — the universal framework currently on screen. */
  complianceId: string;
  /**
   * The exact scan ids backing the overview currently rendered
   * (``attributes.scan_ids``), so the PDF matches what the user sees
   * instead of re-resolving "latest scan per provider" a second time.
   */
  scanIds: string[];
  /**
   * The same ``filter[provider_type__in]`` / ``filter[provider_id__in]`` /
   * ``filter[provider_groups__in]`` values currently applied via
   * ``CrossProviderFilters`` (raw comma-separated strings straight from the
   * URL search params). ``scanIds`` is already narrowed by these — passing
   * them too is defense-in-depth for the edge case where ``scanIds`` ends up
   * empty and generation would otherwise fall back to auto-selecting across
   * every compatible provider instead of respecting an active filter.
   */
  providerTypes?: string;
  providerIds?: string;
  providerGroups?: string;
  /**
   * A report already generated for these exact filters, resolved
   * server-side alongside the page's data fetch — ``null`` means none
   * exists yet (or it went stale because a contributing provider completed
   * a new scan since), so the button shows "Generate" instead of
   * "Download". Whenever the caller's filters change, a fresh value flows
   * in here via a normal prop update (App Router re-runs the server
   * component on navigation) and this component resyncs to it — state is
   * derived per filter signature, so a report invalidated under the previous
   * filters simply stops matching once the signature changes.
   */
  latestPdfReport: LatestCrossProviderPdfReport | null;
  /** Human-readable framework label (e.g. "CSA Cloud Controls Matrix v4.0")
   *  used to pre-fill the "name your report" dialog. */
  frameworkLabel: string;
  className?: string;
}

/** Default report name pre-filled in the dialog: framework + today's date,
 *  so it's descriptive and unique out of the box while still editable. */
const buildDefaultReportName = (frameworkLabel: string) => {
  const today = new Date();
  const yyyy = today.getFullYear();
  const mm = String(today.getMonth() + 1).padStart(2, "0");
  const dd = String(today.getDate()).padStart(2, "0");
  return `${frameworkLabel} - ${yyyy}-${mm}-${dd}`;
};

const formatGeneratedAt = (iso?: string) => {
  if (!iso) return null;
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return null;
  return date.toLocaleString();
};

/**
 * "Generate PDF" / "Download PDF" button for the cross-provider compliance
 * view. Three states:
 *
 *   - No report for the current filters ("idle"): "Generate PDF". Triggers
 *     ad-hoc generation, however long it takes (the backend job has no fixed
 *     time budget). The button does NOT poll itself: it registers the task in
 *     ``useCrossProviderPdfStore`` and the app-wide ``CrossProviderPdfWatcher``
 *     (mounted once in the layout) polls it to completion. That's what lets
 *     the "ready" toast still fire after the user navigates away from this
 *     page — the button unmounts, but the watcher and store persist.
 *   - Mid-generation: "Generating..." (disabled, spinner) — derived from a
 *     ``running`` entry in the store whose signature matches this button's.
 *   - A report exists for the current filters ("available", because the
 *     server resolved one on load or a store generation for this signature
 *     just completed): "Download PDF" — downloads immediately, no regen.
 *
 * Generation does NOT auto-download. When the watcher sees the job finish it
 * fires a "ready" toast whose action links back to the page the report was
 * generated from (where the button is now "Download PDF"); the user chooses
 * when to download.
 *
 * Changing provider/scan filters is a real navigation (URL search params),
 * so the parent re-fetches and this component receives a fresh
 * ``latestPdfReport`` prop; state is derived per filter signature, so a
 * report generated under the previous filters never lingers as "available"
 * after the filters change.
 */
export const GeneratePdfButton = ({
  complianceId,
  scanIds,
  providerTypes,
  providerIds,
  providerGroups,
  latestPdfReport,
  frameworkLabel,
  className,
}: GeneratePdfButtonProps) => {
  const [isStarting, setIsStarting] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);
  // "Name your report" dialog state.
  const [nameDialogOpen, setNameDialogOpen] = useState(false);
  const [reportName, setReportName] = useState("");
  // Server-resolved report that turned out not to be servable when the user
  // actually clicked Download (file expired/cleaned up). Without this, the
  // stale ``latestPdfReport`` prop would keep the button on "Download PDF"
  // forever, every click failing with a toast telling the user to press a
  // Generate button that never appears. Tagged with the filter signature it
  // was invalidated under, so it's derived away (not reset via an effect)
  // the moment the filters change and a fresh ``latestPdfReport`` flows in.
  const [invalidated, setInvalidated] = useState<{
    signature: string;
    taskId: string;
  } | null>(null);

  const generations = useCrossProviderPdfStore((state) => state.generations);
  const trackGeneration = useCrossProviderPdfStore(
    (state) => state.trackGeneration,
  );
  const removeGeneration = useCrossProviderPdfStore(
    (state) => state.removeGeneration,
  );

  // The filter signature this button was rendered for. When it changes
  // (the user picked different providers, or navigated to a different
  // framework), any report generated under the *previous* signature is no
  // longer relevant — state is derived per signature, so it simply stops
  // matching and the button falls back to whatever the server resolved for
  // the new signature (``latestPdfReport``, already correct because it was
  // fetched for these new filters).
  const filterSignature = [
    complianceId,
    scanIds.join(","),
    providerTypes,
    providerIds,
    providerGroups,
  ].join("|");

  // The invalidation only applies to the signature it happened under; once
  // the filters change it stops matching and the button falls back to the
  // freshly resolved ``latestPdfReport`` — no reset effect needed.
  const invalidatedTaskId =
    invalidated?.signature === filterSignature ? invalidated.taskId : null;

  // Derive this button's view straight from the shared store, matched on the
  // signature the generation was started under: a generation started here is
  // only "mine" (and its finished report only offered for download) while the
  // rendered filters still match the ones it was generated for. A ``running``
  // entry takes priority over a ``completed`` one for the same signature —
  // regenerating after invalidating a stale report leaves both, and the button
  // must show "Generating..." (not the old report's "Download").
  const tracked = Object.values(generations);
  const runningForSignature = tracked.find(
    (generation) =>
      generation.signature === filterSignature &&
      generation.status === "running",
  );
  const completedForSignature = tracked.find(
    (generation) =>
      generation.signature === filterSignature &&
      generation.status === "completed" &&
      generation.taskId !== invalidatedTaskId,
  );
  const isGenerating = isStarting || Boolean(runningForSignature);
  const storeReport = completedForSignature
    ? { taskId: completedForSignature.taskId }
    : null;
  const serverReport =
    latestPdfReport && latestPdfReport.taskId !== invalidatedTaskId
      ? latestPdfReport
      : null;
  const availableReport: Pick<LatestCrossProviderPdfReport, "taskId"> &
    Partial<LatestCrossProviderPdfReport> = storeReport ??
    serverReport ?? { taskId: "" };
  const hasAvailableReport = Boolean(storeReport ?? serverReport);

  // Read the live filter signature from a ref inside the async generate
  // handler (refs are exempt from the hook dependency array and always hold
  // the current-render value) so the store entry is tagged with the filters
  // in effect at click time.
  const currentSignatureRef = useRef(filterSignature);
  currentSignatureRef.current = filterSignature;

  const handleGenerate = useCallback(
    async (chosenName: string) => {
      if (isGenerating) return;
      setIsStarting(true);
      const signature = currentSignatureRef.current;
      // Snapshot the page URL (path + filters) now, so the watcher's "ready"
      // toast can link back here even if the user has navigated elsewhere by
      // the time generation finishes.
      const reportUrl = window.location.pathname + window.location.search;
      toast({
        title: "Generating PDF report",
        description:
          "This may take a while — the report combines every provider's latest scan for the current filters. You'll get a notification when it's ready to download; you can keep browsing in the meantime.",
      });

      const trimmedName = chosenName.trim();
      const result = await generateCrossProviderCompliancePdf({
        complianceId,
        scanIds,
        providerTypes,
        providerIds,
        providerGroups,
        // Empty → server falls back to a unique timestamped default.
        reportName: trimmedName.length > 0 ? trimmedName : undefined,
      });
      setIsStarting(false);

      if ("error" in result) {
        toast({
          variant: "destructive",
          title: "Unable to start PDF generation",
          description: result.error,
        });
        return;
      }

      // Hand off to the app-wide watcher: it polls to completion and fires the
      // "ready" toast even if this button unmounts on navigation.
      trackGeneration({ taskId: result.taskId, signature, reportUrl });
    },
    [
      complianceId,
      scanIds,
      providerTypes,
      providerIds,
      providerGroups,
      isGenerating,
      trackGeneration,
    ],
  );

  // Opening the dialog seeds the input with a descriptive default the user
  // can accept or overwrite.
  const openNameDialog = useCallback(() => {
    setReportName(buildDefaultReportName(frameworkLabel));
    setNameDialogOpen(true);
  }, [frameworkLabel]);

  const confirmGenerate = useCallback(() => {
    setNameDialogOpen(false);
    void handleGenerate(reportName);
  }, [handleGenerate, reportName]);

  const handleDownload = useCallback(async () => {
    if (!hasAvailableReport || isDownloading || isGenerating) return;
    setIsDownloading(true);
    toast({
      title: "Download Started",
      description: "Preparing the combined compliance PDF report.",
    });
    try {
      const result = await getCrossProviderCompliancePdf(
        availableReport.taskId,
      );
      if ("pending" in result && result.pending) {
        // The cached report reference is no longer servable (e.g. the
        // underlying file expired/was cleaned up). Invalidate BOTH sources
        // feeding ``availableReport`` — dropping only the store entry would
        // leave the server-resolved ``latestPdfReport`` prop keeping the
        // button on "Download PDF" forever, telling the user to click a
        // Generate button that never appears.
        removeGeneration(availableReport.taskId);
        setInvalidated({
          signature: currentSignatureRef.current,
          taskId: availableReport.taskId,
        });
        toast({
          variant: "destructive",
          title: "Report No Longer Available",
          description:
            "This report isn't ready to download anymore. Click Generate PDF to create a new one.",
        });
        return;
      }
      await downloadFile(
        result,
        "application/pdf",
        "The combined compliance PDF report has been downloaded successfully.",
        toast,
      );
    } finally {
      setIsDownloading(false);
    }
  }, [
    availableReport.taskId,
    hasAvailableReport,
    isDownloading,
    isGenerating,
    removeGeneration,
  ]);

  const buttonClassName = cn(
    "border-button-primary text-button-primary hover:bg-button-primary/10 h-8 px-2 text-xs",
    className,
  );

  const nameDialog = (
    <Dialog open={nameDialogOpen} onOpenChange={setNameDialogOpen}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Name your report</DialogTitle>
          <DialogDescription>
            This becomes the downloaded PDF&apos;s filename. Leave it as is or
            give it a name you&apos;ll recognize later.
          </DialogDescription>
        </DialogHeader>
        <Input
          value={reportName}
          onChange={(e) => setReportName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") {
              e.preventDefault();
              confirmGenerate();
            }
          }}
          placeholder="Report name"
          aria-label="Report name"
          autoFocus
        />
        <DialogFooter>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setNameDialogOpen(false)}
          >
            Cancel
          </Button>
          <Button size="sm" onClick={confirmGenerate}>
            <FileDown className="size-3" />
            Generate
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );

  let button: ReactNode;
  if (isGenerating) {
    button = (
      <Button
        variant="outline"
        size="sm"
        disabled
        aria-label="Generating combined PDF report"
        className={buttonClassName}
      >
        <Loader2 className="size-3 animate-spin" />
        Generating...
      </Button>
    );
  } else if (hasAvailableReport) {
    const generatedAtLabel = formatGeneratedAt(availableReport.generatedAt);
    const downloadButton = (
      <Button
        variant="outline"
        size="sm"
        onClick={handleDownload}
        disabled={isDownloading}
        aria-label="Download combined PDF report"
        className={buttonClassName}
      >
        {isDownloading ? (
          <Loader2 className="size-3 animate-spin" />
        ) : (
          <DownloadIcon className="size-3" />
        )}
        {isDownloading ? "Downloading..." : "Download PDF"}
      </Button>
    );
    button = generatedAtLabel ? (
      <Tooltip>
        <TooltipTrigger asChild>{downloadButton}</TooltipTrigger>
        <TooltipContent>Generated on {generatedAtLabel}</TooltipContent>
      </Tooltip>
    ) : (
      downloadButton
    );
  } else {
    button = (
      <Button
        variant="outline"
        size="sm"
        onClick={openNameDialog}
        aria-label="Generate combined PDF report"
        className={buttonClassName}
      >
        <FileDown className="size-3" />
        Generate PDF
      </Button>
    );
  }

  return (
    <>
      {button}
      {nameDialog}
    </>
  );
};
