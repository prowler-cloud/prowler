"use client";

import { Spacer } from "@heroui/spacer";
import { ArrowLeft } from "lucide-react";
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
import { useToast } from "@/components/ui";
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
  const graphRef = useRef<AttackPathGraphRef>(null);
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

  if (!scanId) {
    return (
      <div className="flex flex-col gap-6">
        <p className="text-sm text-red-600 dark:text-red-400">
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
          className="mb-4 flex items-center gap-2 text-sm text-gray-600 transition-colors hover:text-gray-900 dark:text-gray-400 dark:hover:text-gray-200"
        >
          <ArrowLeft size={16} />
          Back
        </button>
        <h2 className="dark:text-prowler-theme-pale/90 text-xl font-semibold">
          Build Query & Visualize
        </h2>
        <p className="mt-2 text-sm text-gray-600 dark:text-gray-400">
          Create a query to analyze the attack paths in your infrastructure.
        </p>
      </div>

      <Spacer y={2} />

      {/* Query Builder Section */}
      <div className="dark:bg-prowler-blue-400 flex flex-col gap-4 rounded-lg bg-gray-50 p-6">
        {queriesLoading ? (
          <p className="text-sm">Loading queries...</p>
        ) : queriesError ? (
          <p className="text-sm text-red-600 dark:text-red-400">
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
                  selectedQuery={queries.find((q) => q.id === selectedQueryId)}
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
              <div className="rounded bg-red-50 p-3 text-sm text-red-700 dark:bg-red-900/20 dark:text-red-300">
                {graphState.error}
              </div>
            )}
          </>
        )}
      </div>

      <Spacer y={4} />

      {/* Graph Visualization Section */}
      <div className="flex flex-col gap-4">
        <h3 className="dark:text-prowler-theme-pale/90 text-lg font-semibold">
          Attack Path Graph
        </h3>

        {graphState.loading ? (
          <GraphLoading />
        ) : graphState.data &&
          graphState.data.nodes &&
          graphState.data.nodes.length > 0 ? (
          <>
            <GraphControls
              onZoomIn={() => graphRef.current?.zoomIn()}
              onZoomOut={() => graphRef.current?.zoomOut()}
              onFitToScreen={() => graphRef.current?.resetZoom()}
              onExport={() => {
                try {
                  const svgElement = graphRef.current?.getSVGElement();
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
                      error instanceof Error
                        ? error.message
                        : "Failed to export graph",
                    variant: "destructive",
                  });
                }
              }}
            />

            <div className="flex items-start gap-8">
              <div className="flex-1">
                <AttackPathGraph
                  ref={graphRef}
                  data={graphState.data}
                  onNodeClick={handleNodeClick}
                  selectedNodeId={graphState.selectedNodeId}
                />
              </div>
              <div className="hidden lg:block">
                <GraphLegend />
              </div>
            </div>

            {/* Node Detail Panel - Right Slide Sheet */}
            <NodeDetailPanel
              node={graphState.selectedNode}
              onClose={handleCloseDetails}
            />
          </>
        ) : (
          <div className="dark:bg-prowler-blue-400 rounded-lg bg-gray-50 p-8 text-center">
            <p className="text-sm text-gray-600 dark:text-gray-400">
              Select a query and click &quot;Execute Query&quot; to visualize
              the attack path graph
            </p>
          </div>
        )}
      </div>
    </div>
  );
}
