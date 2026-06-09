"use client";

import { ArrowLeft, Info, Maximize2 } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { FormProvider } from "react-hook-form";

import {
  buildAttackPathQueries,
  executeCustomQuery,
  executeQuery,
  getAvailableQueries,
} from "@/actions/attack-paths";
import { adaptQueryResultToGraphData } from "@/actions/attack-paths/query-result.adapter";
import { FindingDetailDrawer } from "@/components/findings/table";
import { PageReady } from "@/components/onboarding";
import { useFindingDetails } from "@/components/resources/table/use-finding-details";
import { AutoRefresh } from "@/components/scans";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
} from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/shadcn/dialog";
import { useToast } from "@/components/ui";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { isCloud } from "@/lib/shared/env";
import {
  attackPathsTour,
  type AttackPathsTourTarget,
  pickDemoQuery,
  pickDemoScan,
} from "@/lib/tours/attack-paths.tour";
import { attackPathsEmptyTour } from "@/lib/tours/attack-paths-empty.tour";
import { useDriverTour } from "@/lib/tours/use-driver-tour";
import type {
  AttackPathQuery,
  AttackPathQueryError,
  GraphNode,
} from "@/types/attack-paths";
import { ATTACK_PATH_QUERY_IDS, SCAN_STATES } from "@/types/attack-paths";

import {
  AttackPathGraph,
  ExecuteButton,
  GraphControls,
  GraphLegend,
  GraphLoading,
  QueryDescription,
  QueryExecutionError,
  QueryParametersForm,
  QuerySelector,
  ScanListTable,
} from "./_components";
import type { GraphHandle } from "./_components/graph/attack-path-graph";
import { useAttackPathScans } from "./_hooks/use-attack-path-scans";
import { useGraphState } from "./_hooks/use-graph-state";
import { useQueryBuilder } from "./_hooks/use-query-builder";
import { exportGraphAsPNG } from "./_lib";

export default function AttackPathsPage() {
  const searchParams = useSearchParams();
  const pathname = usePathname();
  const router = useRouter();
  const scanId = searchParams.get("scanId");
  // Onboarding tours are Cloud-only.
  const onboardingEnabled = isCloud();
  const isAttackPathsReplay =
    onboardingEnabled && searchParams.get("onboarding") === "attack-paths";
  const graphState = useGraphState();
  const finding = useFindingDetails();
  const { toast } = useToast();

  const { scans, scansLoading, refreshScans } = useAttackPathScans({
    onNoReadyScan: isAttackPathsReplay
      ? () => router.push("/scans?onboarding=view-first-scan")
      : undefined,
  });

  const [queriesLoading, setQueriesLoading] = useState(true);
  const [queriesError, setQueriesError] = useState<string | null>(null);
  const [isFullscreenOpen, setIsFullscreenOpen] = useState(false);
  const graphRef = useRef<GraphHandle>(null);
  const fullscreenGraphRef = useRef<GraphHandle>(null);
  const findingNavigationInFlightRef = useRef(false);
  const hasResetRef = useRef(false);
  const graphContainerRef = useRef<HTMLDivElement>(null);

  const [queries, setQueries] = useState<AttackPathQuery[]>([]);

  const queryBuilder = useQueryBuilder(queries);

  const hasReadyScan = scans.some((scan) => scan.attributes.graph_data_ready);
  const hasNoScans = scans.length === 0;

  useDriverTour(attackPathsEmptyTour, {
    enabled: onboardingEnabled && !scansLoading && hasNoScans,
  });

  const { start: startAttackPathsTour } = useDriverTour<AttackPathsTourTarget>(
    attackPathsTour,
    {
      enabled: onboardingEnabled && !scansLoading && hasReadyScan,
      autoOpen: !isAttackPathsReplay,
      // Page owns tour auto-open; OnboardingSequenceBanner is the sole Continue/Exit control.
      // pickDemoScan/pickDemoQuery policy lives in attack-paths.tour.ts.
      stepHandlers: {
        "scan-list": {
          onNext: async ({ waitForStep }) => {
            const selected = pickDemoScan(scans);
            if (!selected) return;
            const params = new URLSearchParams(searchParams.toString());
            params.set("scanId", selected.id);
            router.push(`${pathname}?${params.toString()}`);
            await waitForStep("query-selector");
          },
        },
        "query-selector": {
          onNext: async ({ waitForStep }) => {
            const selected = pickDemoQuery(queries);
            if (!selected) return;
            queryBuilder.handleQueryChange(selected.id);
            await waitForStep("execute-button");
          },
        },
      },
    },
  );

  // Onboarding replay entry: start the tour once and strip the `onboarding`
  // param. Invoked from <AttackPathsReplayTrigger>, which mounts only when the
  // replay conditions hold — so `useMountEffect` fires it exactly once and the
  // old `replayStartedRef` run-once guard is gone.
  const startAttackPathsReplay = () => {
    startAttackPathsTour();

    const params = new URLSearchParams(searchParams.toString());
    params.delete("onboarding");
    const query = params.toString();
    window.history.replaceState(
      null,
      "",
      query ? `${pathname}?${query}` : pathname,
    );
  };

  useEffect(() => {
    if (!hasResetRef.current) {
      hasResetRef.current = true;
      graphState.resetGraph();
    }
  }, [graphState]);

  useEffect(() => {
    graphState.resetGraph();
  }, [scanId]); // eslint-disable-line react-hooks/exhaustive-deps -- reset on scanId change only

  const hasExecutingScan = scans.some(
    (scan) =>
      scan.attributes.state === SCAN_STATES.EXECUTING ||
      scan.attributes.state === SCAN_STATES.SCHEDULED,
  );

  const selectedScan = scans.find((scan) => scan.id === scanId);
  const isViewingPreviousCycleData =
    selectedScan &&
    selectedScan.attributes.graph_data_ready &&
    selectedScan.attributes.state !== SCAN_STATES.COMPLETED;

  useEffect(() => {
    const loadQueries = async () => {
      if (!scanId) {
        setQueriesError("No scan selected");
        setQueriesLoading(false);
        return;
      }

      setQueriesLoading(true);
      try {
        const queriesData = await getAvailableQueries(scanId);

        const availableQueries = buildAttackPathQueries(
          queriesData?.data ?? [],
        );

        if (availableQueries.length > 0) {
          setQueries(availableQueries);
          setQueriesError(null);
        } else {
          setQueries([]);
          setQueriesError("Failed to load available queries");
          toast({
            title: "Error",
            description: "Failed to load queries for this scan",
            variant: "destructive",
          });
        }
      } catch (error) {
        const errorMsg =
          error instanceof Error ? error.message : "Unknown error";
        setQueriesError(errorMsg);
        toast({
          title: "Error",
          description: "Failed to load queries",
          variant: "destructive",
        });
      } finally {
        setQueriesLoading(false);
      }
    };

    loadQueries();
  }, [scanId, toast]);

  const showErrorToast = (title: string, description: string) => {
    toast({
      title,
      description,
      variant: "destructive",
    });
  };

  const handleExecuteQuery = async () => {
    if (!scanId || !queryBuilder.selectedQuery) {
      showErrorToast("Error", "Please select both a scan and a query");
      return;
    }

    const isValid = await queryBuilder.form.trigger();
    if (!isValid) {
      showErrorToast(
        "Validation Error",
        "Please fill in all required parameters",
      );
      return;
    }

    graphState.startLoading();
    graphState.setError(null);

    try {
      const parameters = queryBuilder.getQueryParameters();
      const isCustomQuery =
        queryBuilder.selectedQuery === ATTACK_PATH_QUERY_IDS.CUSTOM;
      const result = isCustomQuery
        ? await executeCustomQuery(scanId, String(parameters?.query ?? ""))
        : await executeQuery(scanId, queryBuilder.selectedQuery, parameters);

      if (result && "error" in result) {
        const apiError = result as AttackPathQueryError;
        graphState.resetGraph();

        if (apiError.status === 404) {
          graphState.resetGraph();
          showErrorToast("No data found", "The query returned no data");
        } else if (apiError.status === 403) {
          graphState.setError("Not enough permissions to execute this query");
          showErrorToast(
            "Error",
            "Not enough permissions to execute this query",
          );
        } else if (apiError.status >= 500) {
          const serverDownMessage =
            "Server is temporarily unavailable. Please try again in a few minutes.";
          graphState.setError(serverDownMessage);
          showErrorToast("Error", serverDownMessage);
        } else {
          graphState.setError(apiError.error);
          showErrorToast("Error", apiError.error);
        }
      } else if (result?.data?.attributes) {
        const graphData = adaptQueryResultToGraphData(result.data.attributes);
        graphState.updateGraphData(graphData);
        toast({
          title: "Success",
          description: "Query executed successfully",
          variant: "default",
        });

        setTimeout(() => {
          graphContainerRef.current?.scrollIntoView({
            behavior: "smooth",
            block: "start",
          });
        }, 100);
      } else {
        graphState.resetGraph();
        graphState.setError("Failed to execute query due to an unknown error");
        showErrorToast(
          "Error",
          "Failed to execute query due to an unknown error",
        );
      }
    } catch (error) {
      const rawErrorMsg =
        error instanceof Error ? error.message : "Failed to execute query";
      const errorMsg = rawErrorMsg.includes("Server Components render")
        ? "Server is temporarily unavailable. Please try again in a few minutes."
        : rawErrorMsg;
      graphState.resetGraph();
      graphState.setError(errorMsg);
      showErrorToast("Error", errorMsg);
    } finally {
      graphState.stopLoading();
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    const isFinding = node.labels.some((label) =>
      label.toLowerCase().includes("finding"),
    );

    if (isFinding) {
      if (findingNavigationInFlightRef.current) {
        return;
      }

      findingNavigationInFlightRef.current = true;
      // Open finding drawer directly, bypassing the node-details modal.
      graphState.enterFilteredView(node.id);
      graphState.selectNode(null); // clear so node-details modal doesn't open first
      void handleViewFinding(String(node.properties?.id || node.id));
      return;
    }

    const sourceData = graphState.fullData || graphState.data;
    const hasFindings = sourceData?.edges?.some((edge) => {
      if (edge.source !== node.id && edge.target !== node.id) return false;
      const otherId = edge.source === node.id ? edge.target : edge.source;
      const otherNode = sourceData.nodes?.find(({ id }) => id === otherId);
      return otherNode?.labels.some((label) =>
        label.toLowerCase().includes("finding"),
      );
    });

    if (hasFindings) {
      graphState.toggleExpandedResource(node.id);
    }
  };

  const handleBackToFullView = () => {
    graphState.exitFilteredView();
  };

  const handleViewFinding = async (findingId: string) => {
    if (!findingId) return;

    try {
      await finding.navigateToFinding(findingId);
    } finally {
      findingNavigationInFlightRef.current = false;
    }
  };

  const handleGraphExport = async (target: "main" | "fullscreen") => {
    const ref = target === "fullscreen" ? fullscreenGraphRef : graphRef;
    const handle = ref.current;
    if (!handle) return;

    try {
      await exportGraphAsPNG(
        handle.getContainerElement(),
        handle.getNodesBounds(),
        "attack-path-graph.png",
        graphState.data,
        {
          expandedResources: graphState.expandedResources,
          isFilteredView: graphState.isFilteredView,
          selectedNodeId: graphState.selectedNodeId,
        },
      );
      toast({
        title: "Success",
        description: "Graph exported",
        variant: "default",
      });
    } catch (error) {
      const description =
        error instanceof Error ? error.message : "Failed to export graph";
      showErrorToast("Export failed", description);
    }
  };

  return (
    <div className="flex flex-col gap-6">
      <AutoRefresh
        hasExecutingScan={hasExecutingScan}
        onRefresh={refreshScans}
      />

      {isAttackPathsReplay && !scansLoading && hasReadyScan && (
        <AttackPathsReplayTrigger onReplay={startAttackPathsReplay} />
      )}

      {/* Enables the navbar replay icon once the initial scan load resolves. */}
      {!scansLoading && <PageReady />}

      <div data-tour-id="attack-paths-intro">
        <p className="text-text-neutral-secondary text-sm">
          Select a scan, build a query, and visualize Attack Paths in your
          infrastructure.
        </p>
        <p className="text-text-neutral-secondary mt-1 text-xs">
          Scans can be selected when data is available. A new scan does not
          interrupt access to existing data.
        </p>
      </div>

      {scansLoading ? (
        <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
          <p className="text-sm">Loading scans...</p>
        </div>
      ) : hasNoScans ? (
        <div data-tour-id="attack-paths-empty-scans-cta">
          <Alert variant="info">
            <Info className="size-4" />
            <AlertTitle>No scans available</AlertTitle>
            <AlertDescription>
              <span>
                You need to run a scan before you can analyze attack paths.{" "}
                <Link href="/scans" className="font-medium underline">
                  Go to Scan Jobs
                </Link>
              </span>
            </AlertDescription>
          </Alert>
        </div>
      ) : (
        <>
          <Suspense fallback={<div>Loading scans...</div>}>
            <ScanListTable scans={scans} />
          </Suspense>

          {isViewingPreviousCycleData && (
            <Alert variant="info">
              <Info className="size-4" />
              <AlertTitle>Viewing data from a previous scan</AlertTitle>
              <AlertDescription>
                This scan is currently{" "}
                {selectedScan.attributes.state === SCAN_STATES.EXECUTING
                  ? `running (${selectedScan.attributes.progress}%)`
                  : selectedScan.attributes.state}
                . The graph data shown is from the last completed cycle.
              </AlertDescription>
            </Alert>
          )}

          {scanId && (
            <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
              {queriesLoading ? (
                <p className="text-sm">Loading queries...</p>
              ) : queriesError ? (
                <QueryExecutionError
                  title="Failed to load queries"
                  error={queriesError}
                />
              ) : (
                <>
                  <FormProvider {...queryBuilder.form}>
                    <div data-tour-id="attack-paths-query-selector">
                      <QuerySelector
                        queries={queries}
                        selectedQueryId={queryBuilder.selectedQuery}
                        onQueryChange={queryBuilder.handleQueryChange}
                      />
                    </div>

                    {queryBuilder.selectedQueryData && (
                      <QueryDescription
                        query={queryBuilder.selectedQueryData}
                      />
                    )}

                    {queryBuilder.selectedQuery && (
                      <QueryParametersForm
                        selectedQuery={queryBuilder.selectedQueryData}
                      />
                    )}
                  </FormProvider>

                  <div
                    data-tour-id="attack-paths-execute-button"
                    className="flex justify-end gap-3"
                  >
                    <ExecuteButton
                      isLoading={graphState.loading}
                      isDisabled={
                        !queryBuilder.selectedQuery ||
                        queryBuilder.isExecutionBlocked
                      }
                      onExecute={handleExecuteQuery}
                    />
                  </div>

                  {graphState.error && (
                    <QueryExecutionError error={graphState.error} />
                  )}
                </>
              )}
            </div>
          )}

          {(graphState.loading ||
            (graphState.data &&
              graphState.data.nodes &&
              graphState.data.nodes.length > 0)) && (
            <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
              {graphState.loading ? (
                <GraphLoading />
              ) : graphState.data &&
                graphState.data.nodes &&
                graphState.data.nodes.length > 0 ? (
                <>
                  <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                    {graphState.isFilteredView ? (
                      <div className="flex items-center gap-3">
                        <Button
                          onClick={handleBackToFullView}
                          variant="outline"
                          size="sm"
                          className="gap-2"
                          aria-label="Return to full graph view"
                        >
                          <ArrowLeft size={16} />
                          Back to Full View
                        </Button>
                        <div
                          className="bg-bg-info-secondary text-text-info inline-flex cursor-default items-center gap-2 rounded-md px-3 py-2 text-xs font-medium shadow-sm sm:px-4 sm:text-sm"
                          role="status"
                          aria-label="Filtered view active"
                        >
                          <span className="flex-shrink-0" aria-hidden="true">
                            🔍
                          </span>
                          <span className="flex-1">
                            Showing paths for:{" "}
                            <strong>
                              {graphState.filteredNode?.properties?.name ||
                                graphState.filteredNode?.properties?.id ||
                                "Selected node"}
                            </strong>
                          </span>
                        </div>
                      </div>
                    ) : (
                      <div
                        className="bg-bg-info-secondary text-text-info inline-flex cursor-default items-center gap-2 rounded-md px-3 py-2 text-xs font-medium shadow-sm sm:px-4 sm:text-sm"
                        role="status"
                        aria-label="Graph interaction instructions"
                      >
                        <span className="flex-shrink-0" aria-hidden="true">
                          💡
                        </span>
                        <span className="flex-1">
                          Click a finding to focus its connected path, or click
                          a resource with findings to show or hide its related
                          findings
                        </span>
                      </div>
                    )}

                    <div className="flex items-center gap-2">
                      <GraphControls
                        onZoomIn={() => graphRef.current?.zoomIn()}
                        onZoomOut={() => graphRef.current?.zoomOut()}
                        onFitToScreen={() => graphRef.current?.resetZoom()}
                        onExport={() => handleGraphExport("main")}
                      />

                      <div className="border-border-neutral-primary bg-bg-neutral-tertiary flex gap-1 rounded-lg border p-1">
                        <Dialog
                          open={isFullscreenOpen}
                          onOpenChange={setIsFullscreenOpen}
                        >
                          <DialogTrigger asChild>
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-8 w-8 p-0"
                              aria-label="Fullscreen"
                            >
                              <Maximize2 size={18} />
                            </Button>
                          </DialogTrigger>
                          <DialogContent className="flex h-full max-h-screen w-full max-w-full flex-col gap-0 rounded-none border-0 p-0 sm:max-w-full">
                            <DialogHeader className="sr-only">
                              <DialogTitle>Fullscreen graph view</DialogTitle>
                              <DialogDescription>
                                Explore the attack path graph at full size. Use
                                the toolbar to zoom, fit, or export the graph.
                              </DialogDescription>
                            </DialogHeader>
                            <div className="px-4 pt-4 pb-4 sm:px-6 sm:pt-6">
                              <GraphControls
                                onZoomIn={() =>
                                  fullscreenGraphRef.current?.zoomIn()
                                }
                                onZoomOut={() =>
                                  fullscreenGraphRef.current?.zoomOut()
                                }
                                onFitToScreen={() =>
                                  fullscreenGraphRef.current?.resetZoom()
                                }
                                onExport={() => handleGraphExport("fullscreen")}
                              />
                            </div>
                            <div className="flex flex-1 flex-col gap-4 overflow-hidden px-4 pb-4 sm:px-6 sm:pb-6 lg:flex-row">
                              <div className="flex flex-1 items-center justify-center">
                                <AttackPathGraph
                                  ref={fullscreenGraphRef}
                                  data={graphState.data}
                                  onNodeClick={handleNodeClick}
                                  selectedNodeId={graphState.selectedNodeId}
                                  isFilteredView={graphState.isFilteredView}
                                  expandedResources={
                                    graphState.expandedResources
                                  }
                                />
                              </div>
                            </div>
                          </DialogContent>
                        </Dialog>
                      </div>
                    </div>
                  </div>

                  <div
                    ref={graphContainerRef}
                    className="h-[calc(100vh-22rem)]"
                  >
                    <AttackPathGraph
                      ref={graphRef}
                      data={graphState.data}
                      onNodeClick={handleNodeClick}
                      selectedNodeId={graphState.selectedNodeId}
                      isFilteredView={graphState.isFilteredView}
                      expandedResources={graphState.expandedResources}
                    />
                  </div>

                  <div className="flex justify-center overflow-x-auto">
                    <GraphLegend
                      data={graphState.data}
                      expandedResources={graphState.expandedResources}
                      isFilteredView={graphState.isFilteredView}
                    />
                  </div>
                </>
              ) : null}
            </div>
          )}

          {finding.findingDetails && (
            <FindingDetailDrawer
              key={finding.findingDetails.id}
              finding={finding.findingDetails}
              defaultOpen
              onOpenChange={(open) => {
                if (!open) finding.resetFindingDetails();
              }}
            />
          )}
        </>
      )}
    </div>
  );
}

interface AttackPathsReplayTriggerProps {
  onReplay: () => void;
}

// Conditional-mount trigger: the parent renders this only when the replay
// should start. The microtask keeps driver.js/flushSync outside React's
// mount lifecycle while still running before the next browser task.
function AttackPathsReplayTrigger({ onReplay }: AttackPathsReplayTriggerProps) {
  useMountEffect(() => {
    let cancelled = false;

    queueMicrotask(() => {
      if (!cancelled) onReplay();
    });

    return () => {
      cancelled = true;
    };
  });

  return null;
}
