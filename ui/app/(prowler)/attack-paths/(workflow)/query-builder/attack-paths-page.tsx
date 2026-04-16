"use client";

import { ArrowLeft, Info, Maximize2, X } from "lucide-react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { FormProvider } from "react-hook-form";

import { cn } from "@/lib/utils";

import {
  buildAttackPathQueries,
  executeCustomQuery,
  executeQuery,
  getAttackPathScans,
  getAvailableQueries,
} from "@/actions/attack-paths";
import { adaptQueryResultToGraphData } from "@/actions/attack-paths/query-result.adapter";
import { FindingDetailDrawer } from "@/components/findings/table";
import { useFindingDetails } from "@/components/resources/table/use-finding-details";
import { AutoRefresh } from "@/components/scans";
import {
  Alert,
  AlertDescription,
  AlertTitle,
  Button,
  Card,
  CardContent,
} from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/shadcn/dialog";
import { Spinner } from "@/components/shadcn/spinner/spinner";
import { useToast } from "@/components/ui";
import type {
  AttackPathQuery,
  AttackPathQueryError,
  AttackPathScan,
  GraphNode,
} from "@/types/attack-paths";
import { ATTACK_PATH_QUERY_IDS, SCAN_STATES } from "@/types/attack-paths";

import {
  AttackPathGraph,
  ExecuteButton,
  GraphControls,
  GraphLegend,
  GraphLoading,
  NodeDetailContent,
  QueryDescription,
  QueryExecutionError,
  QueryParametersForm,
  QuerySelector,
  ScanListTable,
} from "./_components";
import type { GraphHandle } from "./_components/graph/attack-path-graph";
import { useGraphState } from "./_hooks/use-graph-state";
import { useQueryBuilder } from "./_hooks/use-query-builder";

const getNodeDisplayTitle = (node: GraphNode): string => {
  const isFinding = node.labels.some((l) =>
    l.toLowerCase().includes("finding"),
  );
  return String(
    isFinding
      ? node.properties?.check_title || node.properties?.id || "Unknown Finding"
      : node.properties?.name || node.properties?.id || "Unknown Resource",
  );
};

interface NodeDetailPanelProps {
  node: GraphNode;
  allNodes: GraphNode[];
  onClose: () => void;
  headingId: string;
  compact?: boolean;
}

const NodeDetailPanel = ({
  node,
  allNodes,
  onClose,
  headingId,
  compact,
}: NodeDetailPanelProps) => {
  const isFinding = node.labels.some((label) =>
    label.toLowerCase().includes("finding"),
  );

  return (
    <>
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <h3
            id={headingId}
            className={compact ? "text-sm font-semibold" : "text-lg font-semibold"}
          >
            Node Details
          </h3>
          <p
            className={cn(
              "text-text-neutral-secondary dark:text-text-neutral-secondary",
              compact ? "mb-4 text-xs" : "mt-1 text-sm",
            )}
          >
            {getNodeDisplayTitle(node)}
          </p>
        </div>
        <div className="flex items-center gap-2">
          {!compact && isFinding && (
            <Button asChild variant="default" size="sm">
              <a
                href={`/findings?id=${String(node.properties?.id || node.id)}`}
                target="_blank"
                rel="noopener noreferrer"
                aria-label={`View finding ${String(node.properties?.id || node.id)}`}
              >
                View Finding →
              </a>
            </Button>
          )}
          <Button
            onClick={onClose}
            variant="ghost"
            size="sm"
            className={compact ? "h-6 w-6 p-0" : "h-8 w-8 p-0"}
            aria-label="Close node details"
          >
            <X size={16} />
          </Button>
        </div>
      </div>
      <NodeDetailContent node={node} allNodes={allNodes} />
    </>
  );
};

/**
 * Attack Paths
 * Allows users to select a scan, build a query, and visualize the attack path graph
 */
export default function AttackPathsPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scanId");
  const graphState = useGraphState();
  const finding = useFindingDetails();
  const { toast } = useToast();

  const [scansLoading, setScansLoading] = useState(true);
  const [scans, setScans] = useState<AttackPathScan[]>([]);
  const [queriesLoading, setQueriesLoading] = useState(true);
  const [queriesError, setQueriesError] = useState<string | null>(null);
  const [isFullscreenOpen, setIsFullscreenOpen] = useState(false);
  const graphRef = useRef<GraphHandle>(null);
  const fullscreenGraphRef = useRef<GraphHandle>(null);
  const hasResetRef = useRef(false);
  const nodeDetailsRef = useRef<HTMLDivElement>(null);
  const graphContainerRef = useRef<HTMLDivElement>(null);

  const [queries, setQueries] = useState<AttackPathQuery[]>([]);

  // Use custom hook for query builder form state and validation
  const queryBuilder = useQueryBuilder(queries);

  // Reset graph state when component mounts
  useEffect(() => {
    if (!hasResetRef.current) {
      hasResetRef.current = true;
      graphState.resetGraph();
    }
  }, [graphState]);

  // Reset graph state when scan changes
  useEffect(() => {
    graphState.resetGraph();
  }, [scanId]); // eslint-disable-line react-hooks/exhaustive-deps -- reset on scanId change only

  // Load available scans on mount
  useEffect(() => {
    const loadScans = async () => {
      setScansLoading(true);
      try {
        const scansData = await getAttackPathScans();
        if (scansData?.data) {
          setScans(scansData.data);
        } else {
          setScans([]);
        }
      } catch (error) {
        console.error("Failed to load scans:", error);
        setScans([]);
      } finally {
        setScansLoading(false);
      }
    };

    loadScans();
  }, []);

  // Check if there's an executing scan for auto-refresh
  const hasExecutingScan = scans.some(
    (scan) =>
      scan.attributes.state === SCAN_STATES.EXECUTING ||
      scan.attributes.state === SCAN_STATES.SCHEDULED,
  );

  // Detect if the selected scan is showing data from a previous cycle
  const selectedScan = scans.find((scan) => scan.id === scanId);
  const isViewingPreviousCycleData =
    selectedScan &&
    selectedScan.attributes.graph_data_ready &&
    selectedScan.attributes.state !== SCAN_STATES.COMPLETED;

  // Callback to refresh scans (used by AutoRefresh component)
  const refreshScans = async () => {
    try {
      const scansData = await getAttackPathScans();
      if (scansData?.data) {
        setScans(scansData.data);
      }
    } catch (error) {
      console.error("Failed to refresh scans:", error);
    }
  };

  // Load available queries on mount
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

    // Validate form before executing query
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

        // Scroll to graph after successful query execution
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
    // Always select the node (opens detail panel)
    graphState.selectNode(node.id);

    const isFinding = node.labels.some((label) =>
      label.toLowerCase().includes("finding"),
    );

    // Tier 2: clicking a finding node OR any node in filtered view → enter filtered view
    if (isFinding || graphState.isFilteredView) {
      graphState.enterFilteredView(node.id);
    }

    // Scroll to details section for findings
    if (isFinding) {
      setTimeout(() => {
        nodeDetailsRef.current?.scrollIntoView({
          behavior: "smooth",
          block: "nearest",
        });
      }, 100);
    }
  };

  const handleBackToFullView = () => {
    graphState.exitFilteredView();
  };

  const handleCloseDetails = () => {
    graphState.selectNode(null);
  };

  const getFindingId = (node: GraphNode | null) =>
    node ? String(node.properties?.id || node.id) : "";

  const handleViewFinding = (findingId: string) => {
    if (!findingId) return;
    void finding.navigateToFinding(findingId);
  };


  return (
    <div className="flex flex-col gap-6">
      {/* Auto-refresh scans when there's an executing scan */}
      <AutoRefresh
        hasExecutingScan={hasExecutingScan}
        onRefresh={refreshScans}
      />

      {/* Header */}
      <div>
        <h2 className="dark:text-prowler-theme-pale/90 text-xl font-semibold">
          Attack Paths
        </h2>
        <p className="text-text-neutral-secondary mt-2 text-sm">
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
      ) : scans.length === 0 ? (
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
      ) : (
        <>
          {/* Scans Table */}
          <Suspense fallback={<div>Loading scans...</div>}>
            <ScanListTable scans={scans} />
          </Suspense>

          {/* Banner: viewing data from a previous scan cycle */}
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

          {/* Query Builder Section - shown only after selecting a scan */}
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
                    <QuerySelector
                      queries={queries}
                      selectedQueryId={queryBuilder.selectedQuery}
                      onQueryChange={queryBuilder.handleQueryChange}
                    />

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

                  <div className="flex justify-end gap-3">
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

          {/* Graph Visualization (Full Width) */}
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
                  {/* Info message and controls */}
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
                          Click on any node to filter and view its connected
                          paths
                        </span>
                      </div>
                    )}

                    {/* Graph controls and fullscreen button together */}
                    <div className="flex items-center gap-2">
                      <GraphControls
                        onZoomIn={() => graphRef.current?.zoomIn()}
                        onZoomOut={() => graphRef.current?.zoomOut()}
                        onFitToScreen={() => graphRef.current?.resetZoom()}
                      />

                      {/* Fullscreen button */}
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
                                />
                              </div>
                              {/* Node Detail Panel - Side by side */}
                              {graphState.selectedNode && graphState.data && (
                                <section
                                  aria-labelledby="fullscreen-node-details-heading"
                                  className="w-full overflow-y-auto lg:w-96"
                                >
                                  <Card>
                                    <CardContent className="p-4">
                                      <NodeDetailPanel
                                        node={graphState.selectedNode}
                                        allNodes={graphState.data.nodes}
                                        onClose={handleCloseDetails}
                                        headingId="fullscreen-node-details-heading"
                                        compact
                                      />
                                    </CardContent>
                                  </Card>
                                </section>
                              )}
                            </div>
                          </DialogContent>
                        </Dialog>
                      </div>
                    </div>
                  </div>

                  {/* Graph in the middle */}
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
                    />
                  </div>

                  {/* Legend below */}
                  <div className="flex justify-center overflow-x-auto">
                    <GraphLegend data={graphState.data} />
                  </div>
                </>
              ) : null}
            </div>
          )}

          {/* Node Detail Panel - Below Graph */}
          {graphState.selectedNode && graphState.data && (
            <div
              ref={nodeDetailsRef}
              className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4"
            >
              <NodeDetailPanel
                node={graphState.selectedNode}
                allNodes={graphState.data.nodes}
                onClose={handleCloseDetails}
                onViewFinding={handleViewFinding}
                viewFindingLoading={finding.findingDetailLoading}
                headingId="node-details-heading"
              />
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
