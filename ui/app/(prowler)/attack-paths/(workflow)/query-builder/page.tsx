"use client";

import { Spacer } from "@heroui/spacer";
import { ArrowLeft, Maximize2, X } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useRef, useState } from "react";
import { FormProvider, useForm } from "react-hook-form";

import { executeQuery, getAvailableQueries } from "@/actions/attack-paths";
import {
  AttackPathGraph,
  ExecuteButton,
  GraphControls,
  GraphLegend,
  GraphLoading,
  NodeDetailPanel,
  QueryParametersForm,
  QuerySelector,
} from "@/components/attack-paths";
import type { AttackPathGraphRef } from "@/components/attack-paths/graph/attack-path-graph";
import { Button, Card, CardContent } from "@/components/shadcn";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  useToast,
} from "@/components/ui";
import { useGraphState } from "@/hooks/attack-paths/use-graph-state";
import { exportGraphAsSVG } from "@/lib/attack-paths/export";
import type { AttackPathQuery, GraphNode } from "@/types/attack-paths";

/**
 * Step 2: Query Builder & Graph Visualization
 * Allows users to build a query and visualize the attack path graph
 */
export default function QueryBuilderPage() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const scanId = searchParams.get("scanId");
  const graphState = useGraphState();
  const { toast } = useToast();

  const [queries, setQueries] = useState<AttackPathQuery[]>([]);
  const [selectedQueryId, setSelectedQueryId] = useState<string | null>(null);
  const [queriesLoading, setQueriesLoading] = useState(true);
  const [queriesError, setQueriesError] = useState<string | null>(null);
  const [isFullscreenOpen, setIsFullscreenOpen] = useState(false);
  const graphRef = useRef<AttackPathGraphRef>(null);
  const fullscreenGraphRef = useRef<AttackPathGraphRef>(null);
  const hasResetRef = useRef(false);

  const methods = useForm({
    mode: "onChange",
  });

  // Reset graph state when component mounts
  useEffect(() => {
    if (!hasResetRef.current) {
      hasResetRef.current = true;
      graphState.resetGraph();
    }
  }, [graphState]);

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
    setSelectedQueryId(queryId);
    methods.reset();
  };

  const handleExecuteQuery = async () => {
    if (!scanId || !selectedQueryId) {
      toast({
        title: "Error",
        description: "Please select both a scan and a query",
        variant: "destructive",
      });
      return;
    }

    graphState.startLoading();
    graphState.setError(null);

    try {
      const parameters = methods.getValues();
      const result = await executeQuery(scanId, selectedQueryId, parameters);

      if (result?.data?.attributes) {
        graphState.updateGraphData(result.data.attributes);
        toast({
          title: "Success",
          description: "Query executed successfully",
          variant: "default",
        });
      } else {
        graphState.setError("No data returned from query");
        toast({
          title: "Error",
          description: "Query returned no data",
          variant: "destructive",
        });
      }
    } catch (error) {
      const errorMsg =
        error instanceof Error ? error.message : "Failed to execute query";
      graphState.setError(errorMsg);
      toast({
        title: "Error",
        description: errorMsg,
        variant: "destructive",
      });
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

  if (!scanId) {
    return (
      <div className="flex flex-col gap-6">
        <p className="text-text-danger dark:text-text-danger text-sm">
          Error: No scan selected. Please go back and select a scan.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <div>
        <button
          onClick={() => router.back()}
          className="text-text-neutral-secondary hover:text-text-neutral-primary dark:text-text-neutral-secondary dark:hover:text-text-neutral-primary mb-4 flex items-center gap-2 text-sm transition-colors"
        >
          <ArrowLeft size={16} />
          Back
        </button>
        <h2 className="dark:text-prowler-theme-pale/90 text-xl font-semibold">
          Build Query & Visualize
        </h2>
        <p className="text-text-neutral-secondary dark:text-text-neutral-secondary mt-2 text-sm">
          Create a query to analyze the attack paths in your infrastructure.
        </p>
      </div>

      <Spacer y={2} />

      {/* Two Column Layout - Form and Graph */}
      <div className="grid auto-rows-fr grid-cols-1 gap-8 xl:grid-cols-2">
        {/* Query Builder Section - Left Column */}
        <div className="dark:bg-prowler-blue-400 bg-bg-neutral-secondary flex flex-col gap-4 rounded-lg p-6">
          {queriesLoading ? (
            <p className="text-sm">Loading queries...</p>
          ) : queriesError ? (
            <p className="text-text-danger dark:text-text-danger text-sm">
              {queriesError}
            </p>
          ) : (
            <>
              <FormProvider {...methods}>
                <QuerySelector
                  queries={queries}
                  selectedQueryId={selectedQueryId}
                  onQueryChange={handleQueryChange}
                />

                {selectedQueryId && (
                  <QueryParametersForm
                    selectedQuery={queries.find(
                      (q) => q.id === selectedQueryId,
                    )}
                  />
                )}
              </FormProvider>

              <div className="flex gap-3">
                <ExecuteButton
                  isLoading={graphState.loading}
                  isDisabled={!selectedQueryId}
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

        {/* Graph Visualization Section - Right Column */}
        <div className="flex min-h-full flex-col gap-4">
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
                            onZoomIn={() =>
                              fullscreenGraphRef.current?.zoomIn()
                            }
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
                                        {graphState.selectedNode?.labels.join(
                                          ", ",
                                        )}
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
              <div className="h-96">
                <AttackPathGraph
                  ref={graphRef}
                  data={graphState.data}
                  onNodeClick={handleNodeClick}
                  selectedNodeId={graphState.selectedNodeId}
                />
              </div>

              {/* Legend below */}
              <div className="hidden justify-center lg:flex">
                <GraphLegend />
              </div>
            </>
          ) : (
            <div className="dark:bg-prowler-blue-400 bg-bg-neutral-secondary flex flex-1 items-center justify-center rounded-lg p-8 text-center">
              <p className="text-text-neutral-secondary dark:text-text-neutral-secondary text-sm">
                Select a query and click &quot;Execute Query&quot; to visualize
                the attack path graph
              </p>
            </div>
          )}

          {/* Node Detail Panel - Right Slide Sheet */}
          {graphState.data &&
            graphState.data.nodes &&
            graphState.data.nodes.length > 0 && (
              <NodeDetailPanel
                node={graphState.selectedNode}
                onClose={handleCloseDetails}
              />
            )}
        </div>
      </div>
    </div>
  );
}
