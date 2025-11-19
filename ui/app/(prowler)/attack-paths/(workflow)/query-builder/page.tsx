"use client";

import { Maximize2, X } from "lucide-react";
import { useSearchParams } from "next/navigation";
import { Suspense, useEffect, useRef, useState } from "react";
import { FormProvider } from "react-hook-form";

import {
  executeQuery,
  getAttackPathScans,
  getAvailableQueries,
} from "@/actions/attack-paths";
import { adaptQueryResultToGraphData } from "@/actions/attack-paths/query-result.adapter";
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
  NodeDetailPanel,
  QueryParametersForm,
  QuerySelector,
  ScanListTable,
} from "./_components";
import type { AttackPathGraphRef } from "./_components/graph/attack-path-graph";
import { useGraphState } from "./_hooks/use-graph-state";
import { useQueryBuilder } from "./_hooks/use-query-builder";
import { exportGraphAsSVG, formatNodeLabel } from "./_lib";

/**
 * Attack Path Analysis
 * Allows users to select a scan, build a query, and visualize the attack path graph
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

      if (result?.data?.attributes) {
        const graphData = adaptQueryResultToGraphData(result.data.attributes);
        graphState.updateGraphData(graphData);
        toast({
          title: "Success",
          description: "Query executed successfully",
          variant: "default",
        });
      } else {
        graphState.setError("No data returned from query");
        showErrorToast("Error", "Query returned no data");
      }
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Failed to execute query";
      graphState.setError(errorMsg);
      showErrorToast("Error", errorMsg);
    } finally {
      graphState.stopLoading();
    }
  };

  const handleNodeClick = (node: GraphNode) => {
    graphState.selectNode(node.id);
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
      {/* Header */}
      <div>
        <h2 className="dark:text-prowler-theme-pale/90 text-xl font-semibold">
          Attack Path Analysis
        </h2>
        <p className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-2 text-sm">
          Select a scan, build a query, and visualize attack paths in your
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
            {/* Controls on top */}
            <div className="flex items-stretch justify-end gap-2">
              <GraphControls
                onZoomIn={() => graphRef.current?.zoomIn()}
                onZoomOut={() => graphRef.current?.zoomOut()}
                onFitToScreen={() => graphRef.current?.resetZoom()}
                onExport={() =>
                  handleGraphExport(graphRef.current?.getSVGElement() || null)
                }
              />

              {/* Fullscreen button */}
              <div className="mb-4 flex items-center">
                <div className="border-border-neutral-primary bg-bg-neutral-tertiary dark:border-border-neutral-primary dark:bg-bg-neutral-tertiary flex gap-1 rounded-lg border p-1">
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
                                  {`${graphState.selectedNode?.properties?.name || graphState.selectedNode?.id.substring(0, 20)}`}
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
            <div className="h-screen">
              <AttackPathGraph
                ref={graphRef}
                data={graphState.data}
                onNodeClick={handleNodeClick}
                selectedNodeId={graphState.selectedNodeId}
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
              the attack path graph
            </p>
          </div>
        )}
      </div>

      {/* Node Detail Panel - Right Slide Sheet */}
      {graphState.data &&
        graphState.data.nodes &&
        graphState.data.nodes.length > 0 && (
          <NodeDetailPanel
            node={graphState.selectedNode}
            allNodes={graphState.data?.nodes}
            onClose={handleCloseDetails}
          />
        )}
    </div>
  );
}
