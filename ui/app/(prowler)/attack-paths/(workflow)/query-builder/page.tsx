"use client";

import { ArrowLeft, Maximize2, X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Suspense, useCallback, useEffect, useRef, useState } from "react";
import { FormProvider } from "react-hook-form";

import {
  executeQuery,
  getAttackPathScans,
  getAvailableQueries,
} from "@/actions/attack-paths";
import { adaptQueryResultToGraphData } from "@/actions/attack-paths/query-result.adapter";
import { AutoRefresh } from "@/components/scans";
import { Button, Card, CardContent } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  useToast,
} from "@/components/ui";
import type {
  AttackPathQuery,
  AttackPathScan,
  GraphNode,
} from "@/types/attack-paths";

import {
  AttackPathGraph,
  ExecuteButton,
  GraphControls,
  GraphLegend,
  GraphLoading,
  NodeDetailContent,
  QueryParametersForm,
  QuerySelector,
  ScanListTable,
} from "./_components";
import type { AttackPathGraphRef } from "./_components/graph/attack-path-graph";
import { useGraphState } from "./_hooks/use-graph-state";
import { useQueryBuilder } from "./_hooks/use-query-builder";
import { exportGraphAsSVG, formatNodeLabel } from "./_lib";

/**
 * Attack Paths Analysis
 * Allows users to select a scan, build a query, and visualize the Attack Paths graph
 */
export default function AttackPathAnalysisPage() {
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scanId");
  const graphState = useGraphState();
  const { toast } = useToast();

  const [scansLoading, setScansLoading] = useState(true);
  const [scans, setScans] = useState<AttackPathScan[]>([]);
  const [queriesLoading, setQueriesLoading] = useState(true);
  const [queriesError, setQueriesError] = useState<string | null>(null);
  const [isFullscreenOpen, setIsFullscreenOpen] = useState(false);
  const graphRef = useRef<AttackPathGraphRef>(null);
  const fullscreenGraphRef = useRef<AttackPathGraphRef>(null);
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
      scan.attributes.state === "executing" ||
      scan.attributes.state === "scheduled",
  );

  // Callback to refresh scans (used by AutoRefresh component)
  const refreshScans = useCallback(async () => {
    try {
      const scansData = await getAttackPathScans();
      if (scansData?.data) {
        setScans(scansData.data);
      }
    } catch (error) {
      console.error("Failed to refresh scans:", error);
    }
  }, []);

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
        if (queriesData?.data) {
          setQueries(queriesData.data);
          setQueriesError(null);
        } else {
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

  const handleQueryChange = (queryId: string) => {
    queryBuilder.handleQueryChange(queryId);
  };

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
      const parameters = queryBuilder.getQueryParameters() as Record<
        string,
        string | number | boolean
      >;
      const result = await executeQuery(
        scanId,
        queryBuilder.selectedQuery,
        parameters,
      );

      if (result && "error" in result) {
        const apiError = result as unknown as { error: string; status: number };
        graphState.resetGraph();

        if (apiError.status === 404) {
          graphState.setError("No data found");
          showErrorToast("No data found", "The query returned no data");
        } else if (apiError.status === 403) {
          graphState.setError("Not enough permissions to execute this query");
          showErrorToast(
            "Error",
            "Not enough permissions to execute this query",
          );
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
      const errorMsg =
        error instanceof Error ? error.message : "Failed to execute query";
      graphState.resetGraph();
      graphState.setError(errorMsg);
      showErrorToast("Error", errorMsg);
    } finally {
      graphState.stopLoading();
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    // Enter filtered view showing only paths containing this node
    graphState.enterFilteredView(node.id);

    // For findings, also scroll to the details section
    const isFinding = node.labels.some((label) =>
      label.toLowerCase().includes("finding"),
    );

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

  const handleGraphExport = (svgElement: SVGSVGElement | null) => {
    try {
      if (svgElement) {
        exportGraphAsSVG(svgElement, "attack-path-graph.svg");
        toast({
          title: "Success",
          description: "Graph exported as SVG",
          variant: "default",
        });
      } else {
        throw new Error("Could not find graph element");
      }
    } catch (error) {
      toast({
        title: "Error",
        description:
          error instanceof Error ? error.message : "Failed to export graph",
        variant: "destructive",
      });
    }
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
          Attack Paths Analysis
        </h2>
        <p className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-2 text-sm">
          Select a scan, build a query, and visualize Attack Paths in your
          infrastructure.
        </p>
      </div>

      {/* Top Section - Scans Table and Query Builder (2 columns) */}
      <div className="grid grid-cols-1 gap-8 xl:grid-cols-2">
        {/* Scans Table Section - Left Column */}
        <div>
          {scansLoading ? (
            <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
              <p className="text-sm">Loading scans...</p>
            </div>
          ) : scans.length === 0 ? (
            <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
              <p className="text-sm">No scans available</p>
            </div>
          ) : (
            <Suspense fallback={<div>Loading scans...</div>}>
              <ScanListTable scans={scans} />
            </Suspense>
          )}
        </div>

        {/* Query Builder Section - Right Column */}
        <div className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4">
          {!scanId ? (
            <p className="text-text-info dark:text-text-info text-sm">
              Select a scan from the table on the left to begin.
            </p>
          ) : queriesLoading ? (
            <p className="text-sm">Loading queries...</p>
          ) : queriesError ? (
            <p className="text-text-danger dark:text-text-danger text-sm">
              {queriesError}
            </p>
          ) : (
            <>
              <FormProvider {...queryBuilder.form}>
                <QuerySelector
                  queries={queries}
                  selectedQueryId={queryBuilder.selectedQuery}
                  onQueryChange={handleQueryChange}
                />

                {queryBuilder.selectedQueryData && (
                  <div className="bg-bg-neutral-tertiary text-text-neutral-secondary dark:text-text-neutral-secondary rounded-md p-3 text-sm">
                    <p className="whitespace-pre-line">
                      {queryBuilder.selectedQueryData.attributes.description}
                    </p>
                    {queryBuilder.selectedQueryData.attributes.attribution && (
                      <p className="mt-2 text-xs">
                        Source:{" "}
                        <a
                          href={
                            queryBuilder.selectedQueryData.attributes
                              .attribution.link
                          }
                          target="_blank"
                          rel="noopener noreferrer"
                          className="underline"
                        >
                          {
                            queryBuilder.selectedQueryData.attributes
                              .attribution.text
                          }
                        </a>
                      </p>
                    )}
                  </div>
                )}

                {queryBuilder.selectedQuery && (
                  <QueryParametersForm
                    selectedQuery={queryBuilder.selectedQueryData}
                  />
                )}
              </FormProvider>

              <div className="flex gap-3">
                <ExecuteButton
                  isLoading={graphState.loading}
                  isDisabled={!queryBuilder.selectedQuery}
                  onExecute={handleExecuteQuery}
                />
              </div>

              {graphState.error && (
                <div className="bg-bg-danger-secondary text-text-danger dark:bg-bg-danger-secondary dark:text-text-danger rounded p-3 text-sm">
                  {graphState.error}
                </div>
              )}
            </>
          )}
        </div>
      </div>

      {/* Bottom Section - Graph Visualization (Full Width) */}
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
                  className="bg-button-primary inline-flex cursor-default items-center gap-2 rounded-md px-3 py-2 text-xs font-medium text-black shadow-sm sm:px-4 sm:text-sm"
                  role="status"
                  aria-label="Graph interaction instructions"
                >
                  <span className="flex-shrink-0" aria-hidden="true">
                    💡
                  </span>
                  <span className="flex-1">
                    Click on any node to filter and view its connected paths
                  </span>
                </div>
              )}

              {/* Graph controls and fullscreen button together */}
              <div className="flex items-center gap-2">
                <GraphControls
                  onZoomIn={() => graphRef.current?.zoomIn()}
                  onZoomOut={() => graphRef.current?.zoomOut()}
                  onFitToScreen={() => graphRef.current?.resetZoom()}
                  onExport={() =>
                    handleGraphExport(graphRef.current?.getSVGElement() || null)
                  }
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
                    <DialogContent className="flex h-full max-h-screen w-full max-w-full flex-col gap-0 p-0">
                      <DialogHeader className="px-4 pt-4 sm:px-6 sm:pt-6">
                        <DialogTitle className="text-lg">
                          Graph Fullscreen View
                        </DialogTitle>
                      </DialogHeader>
                      <div className="px-4 pt-4 pb-4 sm:px-6 sm:pt-6">
                        <GraphControls
                          onZoomIn={() => fullscreenGraphRef.current?.zoomIn()}
                          onZoomOut={() =>
                            fullscreenGraphRef.current?.zoomOut()
                          }
                          onFitToScreen={() =>
                            fullscreenGraphRef.current?.resetZoom()
                          }
                          onExport={() =>
                            handleGraphExport(
                              fullscreenGraphRef.current?.getSVGElement() ||
                                null,
                            )
                          }
                        />
                      </div>
                      <div className="flex flex-1 gap-4 overflow-hidden px-4 pb-4 sm:px-6 sm:pb-6">
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
                        {graphState.selectedNode && (
                          <section aria-labelledby="node-details-heading">
                            <Card className="w-96 overflow-y-auto">
                              <CardContent className="p-4">
                                <div className="mb-4 flex items-center justify-between">
                                  <h3
                                    id="node-details-heading"
                                    className="text-sm font-semibold"
                                  >
                                    Node Details
                                  </h3>
                                  <Button
                                    onClick={handleCloseDetails}
                                    variant="ghost"
                                    size="sm"
                                    className="h-6 w-6 p-0"
                                    aria-label="Close node details"
                                  >
                                    <X size={16} />
                                  </Button>
                                </div>
                                <p className="text-text-neutral-secondary dark:text-text-neutral-secondary mb-4 text-xs">
                                  {graphState.selectedNode?.labels.some(
                                    (label) =>
                                      label.toLowerCase().includes("finding"),
                                  )
                                    ? graphState.selectedNode?.properties
                                        ?.check_title ||
                                      graphState.selectedNode?.properties?.id ||
                                      "Unknown Finding"
                                    : graphState.selectedNode?.properties
                                        ?.name ||
                                      graphState.selectedNode?.properties?.id ||
                                      "Unknown Resource"}
                                </p>
                                <div className="flex flex-col gap-4">
                                  <div>
                                    <h4 className="mb-2 text-xs font-semibold">
                                      Type
                                    </h4>
                                    <p className="text-text-neutral-secondary dark:text-text-neutral-secondary text-xs">
                                      {graphState.selectedNode?.labels
                                        .map(formatNodeLabel)
                                        .join(", ")}
                                    </p>
                                  </div>
                                </div>
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
            <div ref={graphContainerRef} className="h-[calc(100vh-22rem)]">
              <AttackPathGraph
                ref={graphRef}
                data={graphState.data}
                onNodeClick={handleNodeClick}
                selectedNodeId={graphState.selectedNodeId}
                isFilteredView={graphState.isFilteredView}
              />
            </div>

            {/* Legend below */}
            <div className="hidden justify-center lg:flex">
              <GraphLegend data={graphState.data} />
            </div>
          </>
        ) : (
          <div className="flex flex-1 items-center justify-center text-center">
            <p className="text-text-neutral-secondary dark:text-text-neutral-secondary text-sm">
              Select a query and click &quot;Execute Query&quot; to visualize
              the Attack Paths graph
            </p>
          </div>
        )}
      </div>

      {/* Node Detail Panel - Below Graph */}
      {graphState.selectedNode && graphState.data && (
        <div
          ref={nodeDetailsRef}
          className="minimal-scrollbar rounded-large shadow-small border-border-neutral-secondary bg-bg-neutral-secondary relative z-0 flex w-full flex-col gap-4 overflow-auto border p-4"
        >
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <h3 className="text-lg font-semibold">Node Details</h3>
              <p className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-1 text-sm">
                {String(
                  graphState.selectedNode.labels.some((label) =>
                    label.toLowerCase().includes("finding"),
                  )
                    ? graphState.selectedNode.properties?.check_title ||
                        graphState.selectedNode.properties?.id ||
                        "Unknown Finding"
                    : graphState.selectedNode.properties?.name ||
                        graphState.selectedNode.properties?.id ||
                        "Unknown Resource",
                )}
              </p>
            </div>
            <div className="flex items-center gap-2">
              {graphState.selectedNode.labels.some((label) =>
                label.toLowerCase().includes("finding"),
              ) && (
                <Button asChild variant="default" size="sm">
                  <a
                    href={`/findings?id=${String(graphState.selectedNode.properties?.id || graphState.selectedNode.id)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    aria-label={`View finding ${String(graphState.selectedNode.properties?.id || graphState.selectedNode.id)}`}
                  >
                    View Finding →
                  </a>
                </Button>
              )}
              <Button
                onClick={handleCloseDetails}
                variant="ghost"
                size="sm"
                className="h-8 w-8 p-0"
                aria-label="Close node details"
              >
                <X size={16} />
              </Button>
            </div>
          </div>

          <NodeDetailContent
            node={graphState.selectedNode}
            allNodes={graphState.data.nodes}
          />
        </div>
      )}
    </div>
  );
}
