"use client";

import { ArrowLeft, Maximize2 } from "lucide-react";
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
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { PageReady } from "@/components/onboarding";
import { useFindingDetails } from "@/components/resources/table/use-finding-details";
import { AutoRefresh } from "@/components/scans";
import { Button, Card, useToast } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/shadcn/dialog";
import { StatusAlert } from "@/components/shared/status-alert";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { buildAttackPathContext } from "@/lib/lighthouse/context/contributions";
import { isCloud } from "@/lib/shared/env";
import { attackPathsEmptyTour } from "@/lib/tours/attack-paths-empty.tour";
import {
  attackPathsTour,
  type AttackPathsTourTarget,
  pickDemoQuery,
  pickDemoScan,
} from "@/lib/tours/attack-paths.tour";
import { advanceActiveTour, useDriverTour } from "@/lib/tours/use-driver-tour";
import type {
  AttackPathQuery,
  AttackPathQueryError,
  GraphNode,
  AttackPathOutcome,
} from "@/types/attack-paths";
import {
  ATTACK_PATH_QUERY_IDS,
  ATTACK_PATH_QUERY_KIND,
  SCAN_STATES,
} from "@/types/attack-paths";

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
import { AttackPathsStatusPanel } from "./_components/attack-paths-status-panel";
import type { GraphHandle } from "./_components/graph/attack-path-graph";
import { useAttackPathScans } from "./_hooks/use-attack-path-scans";
import { useGraphState } from "./_hooks/use-graph-state";
import { useQueryBuilder } from "./_hooks/use-query-builder";
import { exportGraphAsPNG, isProwlerFindingNode } from "./_lib";
import {
  ATTACK_PATHS_VIEW_STATES,
  getAttackPathsViewState,
  getGraphBuildingProgress,
  isScanInFlight,
} from "./_lib/get-attack-paths-view-state";
import {
  buildAttackPathView,
  GROUP_NODE_LABEL,
  GROUP_PROPS,
  OUTCOME_NODE_LABEL,
} from "./_lib/group-graph";

const SCROLL_CONTAINER_CLASS =
  "minimal-scrollbar relative z-0 w-full gap-4 overflow-auto shadow-sm";

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

  const { scans, scansLoading, loadError, refreshScans, retryLoadScans } =
    useAttackPathScans({
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
  // Snapshot of the executed query's outcome, so the graph's terminal node
  // reflects the query that produced the current graph (not a later selection).
  const [executedOutcome, setExecutedOutcome] =
    useState<AttackPathOutcome | null>(null);

  const queryBuilder = useQueryBuilder(queries);

  const hasReadyScan = scans.some((scan) => scan.attributes.graph_data_ready);
  const hasNoScans = scans.length === 0;

  useDriverTour(attackPathsEmptyTour, {
    // Gate on !loadError: the empty-scans CTA anchor only renders in the
    // NO_SCANS view-state, not in the ERROR state (which also has scans === []).
    enabled: onboardingEnabled && !scansLoading && !loadError && hasNoScans,
  });

  const { start: startAttackPathsTour } = useDriverTour<AttackPathsTourTarget>(
    attackPathsTour,
    {
      enabled: onboardingEnabled && !scansLoading && hasReadyScan,
      autoOpen: !isAttackPathsReplay,
      // Page owns tour auto-open; OnboardingSequenceBanner is the sole Continue/Skip control.
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

  // Poll while a scan is in flight so the page auto-advances when the graph is ready.
  const hasScanInFlight = isScanInFlight(scans);

  const viewState = getAttackPathsViewState({ scansLoading, loadError, scans });

  // Detect if the selected scan is showing data from a previous cycle
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

    // The tour's execute step is autoAdvance: the real Execute click moves it forward.
    advanceActiveTour();

    graphState.startLoading();
    graphState.setError(null);

    try {
      const queryId = queryBuilder.selectedQuery;
      const queryLabel =
        queryBuilder.selectedQueryData?.attributes.name ?? queryId;
      const parameters = { ...queryBuilder.getQueryParameters() };
      const isCustomQuery = queryId === ATTACK_PATH_QUERY_IDS.CUSTOM;
      // Snapshot before awaiting: the selected query can change while the
      // request is in flight. Custom queries have no catalog outcome → null.
      const queryOutcome = isCustomQuery
        ? null
        : (queryBuilder.selectedQueryData?.attributes.outcome ?? null);
      const result = isCustomQuery
        ? await executeCustomQuery(scanId, String(parameters?.query ?? ""))
        : await executeQuery(scanId, queryId, parameters);

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
        graphState.updateGraphData(graphData, {
          queryId,
          queryLabel,
          queryKind: isCustomQuery
            ? ATTACK_PATH_QUERY_KIND.CUSTOM
            : ATTACK_PATH_QUERY_KIND.PREDEFINED,
          parameters,
        });
        setExecutedOutcome(queryOutcome);
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

  // Shared attack-path view: the same grouped/outcome transform the graph
  // renders, computed here so the PNG export and collapse-state pruning use the
  // exact view the user sees. Cloud-only (OSS keeps the flat graph).
  const attackPathView =
    isCloud() && graphState.data
      ? buildAttackPathView({
          data: graphState.data,
          expandedClasses: graphState.expandedClasses,
          outcome: executedOutcome,
        })
      : null;

  const membersOfClass = (classKey: string): string[] =>
    attackPathView?.groupMembers.get(classKey) ?? [];

  // Collapse every open class, pruning findings-expansion/selection that pointed
  // at any member the collapse hides.
  const handleCollapseAll = () => {
    const memberIds = Array.from(graphState.expandedClasses).flatMap(
      membersOfClass,
    );
    graphState.collapseAllClasses(memberIds);
  };

  const handleNodeClick = (node: GraphNode) => {
    // A collapsed class group expands to its members; the outcome node is inert.
    if (node.labels.includes(GROUP_NODE_LABEL)) {
      const key = String(node.properties[GROUP_PROPS.KEY] ?? "");
      if (key) graphState.toggleExpandedClass(key, membersOfClass(key));
      return;
    }
    if (node.labels.includes(OUTCOME_NODE_LABEL)) {
      return;
    }

    const isFinding = isProwlerFindingNode(node.labels);

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
      return otherNode ? isProwlerFindingNode(otherNode.labels) : false;
    });

    if (hasFindings) {
      // Highlight the resource whose findings are on screen; clear on collapse.
      const willExpand = !graphState.expandedResources.has(node.id);
      graphState.toggleExpandedResource(node.id);
      graphState.selectNode(willExpand ? node.id : null);
    }
  };

  // Double-click a member (or its group) collapses its class back.
  const handleNodeDoubleClick = (node: GraphNode) => {
    const memberKey = node.properties[GROUP_PROPS.MEMBER_KEY];
    if (memberKey) {
      const key = String(memberKey);
      graphState.toggleExpandedClass(key, membersOfClass(key));
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

    // Export the same grouped/outcome view the canvas renders (Cloud); OSS
    // exports the raw flat graph.
    const exportData = attackPathView
      ? { nodes: attackPathView.nodes, edges: attackPathView.edges }
      : graphState.data;

    try {
      await exportGraphAsPNG(
        handle.getContainerElement(),
        handle.getNodesBounds(),
        "attack-path-graph.png",
        exportData,
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

  const lighthouseSelectedNode =
    graphState.selectedNode ?? graphState.filteredNode;
  const lighthouseGraphData = graphState.fullData ?? graphState.data;
  const lighthouseExecution = graphState.loading ? null : graphState.execution;
  const lighthouseContext = scanId
    ? buildAttackPathContext({
        pathname,
        scanId,
        queryId: lighthouseExecution?.queryId,
        queryLabel: lighthouseExecution?.queryLabel,
        queryKind: lighthouseExecution?.queryKind,
        parameters: lighthouseExecution?.parameters,
        graphData: lighthouseExecution ? lighthouseGraphData : null,
        selectedNode:
          lighthouseExecution && lighthouseSelectedNode
            ? {
                id: lighthouseSelectedNode.id,
                type: lighthouseSelectedNode.labels[0],
              }
            : null,
      })
    : null;

  return (
    <div className="flex flex-col gap-6">
      <AutoRefresh
        hasExecutingScan={hasScanInFlight}
        onRefresh={refreshScans}
      />

      {isAttackPathsReplay && !scansLoading && hasReadyScan && (
        <AttackPathsReplayTrigger onReplay={startAttackPathsReplay} />
      )}

      {/* Enables the navbar replay icon once the initial scan load resolves. */}
      {!scansLoading && <PageReady />}

      {lighthouseContext && (
        <LighthouseContextContributor
          key={JSON.stringify(lighthouseContext)}
          contributorId="attack-path-current"
          item={lighthouseContext}
        />
      )}

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

      {viewState === ATTACK_PATHS_VIEW_STATES.LOADING ? (
        <Card variant="base" className={SCROLL_CONTAINER_CLASS}>
          <p className="text-sm">Loading scans...</p>
        </Card>
      ) : viewState === ATTACK_PATHS_VIEW_STATES.NO_SCANS ? (
        // Keep the empty-scans tour anchor: attackPathsEmptyTour targets
        // data-tour-id="attack-paths-empty-scans-cta". The panel's NO_SCANS
        // render is the same "No scans available" + Go to Scan Jobs CTA.
        <div data-tour-id="attack-paths-empty-scans-cta">
          <AttackPathsStatusPanel state={viewState} />
        </div>
      ) : viewState !== ATTACK_PATHS_VIEW_STATES.READY ? (
        <AttackPathsStatusPanel
          state={viewState}
          progress={getGraphBuildingProgress(scans)}
          onRetry={retryLoadScans}
        />
      ) : (
        <>
          <Suspense fallback={<div>Loading scans...</div>}>
            <ScanListTable scans={scans} />
          </Suspense>

          {isViewingPreviousCycleData && (
            <StatusAlert
              variant="info"
              title="Viewing data from a previous scan"
            >
              This scan is currently{" "}
              {selectedScan.attributes.state === SCAN_STATES.EXECUTING
                ? `running (${selectedScan.attributes.progress}%)`
                : selectedScan.attributes.state}
              . The graph data shown is from the last completed cycle.
            </StatusAlert>
          )}

          {scanId && (
            <Card variant="base" className={SCROLL_CONTAINER_CLASS}>
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
            </Card>
          )}

          {(graphState.loading ||
            (graphState.data &&
              graphState.data.nodes &&
              graphState.data.nodes.length > 0)) && (
            <Card variant="base" className={SCROLL_CONTAINER_CLASS}>
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
                        collapseAll={{
                          can: graphState.expandedClasses.size > 0,
                          onCollapse: handleCollapseAll,
                        }}
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
                                collapseAll={{
                                  can: graphState.expandedClasses.size > 0,
                                  onCollapse: handleCollapseAll,
                                }}
                              />
                            </div>
                            <div className="flex flex-1 flex-col gap-4 overflow-hidden px-4 pb-4 sm:px-6 sm:pb-6 lg:flex-row">
                              <div className="flex flex-1 items-center justify-center">
                                <AttackPathGraph
                                  ref={fullscreenGraphRef}
                                  data={graphState.data}
                                  onNodeClick={handleNodeClick}
                                  onNodeDoubleClick={handleNodeDoubleClick}
                                  selectedNodeId={graphState.selectedNodeId}
                                  isFilteredView={graphState.isFilteredView}
                                  expandedResources={
                                    graphState.expandedResources
                                  }
                                  expandedClasses={graphState.expandedClasses}
                                  outcome={executedOutcome}
                                  view={attackPathView}
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
                      onNodeDoubleClick={handleNodeDoubleClick}
                      selectedNodeId={graphState.selectedNodeId}
                      isFilteredView={graphState.isFilteredView}
                      expandedResources={graphState.expandedResources}
                      expandedClasses={graphState.expandedClasses}
                      outcome={executedOutcome}
                      view={attackPathView}
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
            </Card>
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
