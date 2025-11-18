"use client";

import { Card, CardContent } from "@/components/shadcn";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet/sheet";
import type { GraphEdge, GraphNode } from "@/types/attack-paths";

import { NodeOverview } from "./node-overview";
import { NodeRelationships } from "./node-relationships";
import { NodeRemediation } from "./node-remediation";

interface NodeDetailPanelProps {
  node: GraphNode | null;
  incomingEdges?: GraphEdge[];
  outgoingEdges?: GraphEdge[];
  relatedFindings?: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    status: "PASS" | "FAIL" | "MANUAL";
  }>;
  onClose?: () => void;
}

/**
 * Right-side sheet panel for node details
 * Shows comprehensive information about selected graph node
 * Uses shadcn Sheet component for sliding panel from right
 */
export const NodeDetailPanel = ({
  node,
  incomingEdges = [],
  outgoingEdges = [],
  relatedFindings = [],
  onClose,
}: NodeDetailPanelProps) => {
  const isOpen = node !== null;

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose?.()}>
      <SheetContent className="dark:bg-prowler-theme-midnight my-4 max-h-[calc(100vh-2rem)] max-w-[95vw] overflow-y-auto rounded-l-xl pt-10 md:my-8 md:max-h-[calc(100vh-4rem)] md:max-w-[55vw]">
        <SheetHeader>
          <SheetTitle>Node Details</SheetTitle>
          <SheetDescription>
            {String(node?.properties?.name || node?.id.substring(0, 20))}
          </SheetDescription>
        </SheetHeader>

        {node && (
          <div className="flex flex-col gap-6 pt-6">
            {/* Node Overview Section */}
            <Card>
              <CardContent className="flex flex-col gap-3 p-4">
                <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
                  Node Overview
                </h3>
                <div className="text-xs text-gray-600 dark:text-gray-400">
                  Type: {node.labels.join(", ")}
                </div>
                <NodeOverview node={node} />
              </CardContent>
            </Card>

            {/* Relationships Section */}
            <Card>
              <CardContent className="flex flex-col gap-3 p-4">
                <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
                  Relationships
                </h3>
                <div className="text-xs text-gray-600 dark:text-gray-400">
                  {incomingEdges.length} incoming, {outgoingEdges.length}{" "}
                  outgoing
                </div>
                <NodeRelationships
                  incomingEdges={incomingEdges}
                  outgoingEdges={outgoingEdges}
                />
              </CardContent>
            </Card>

            {/* Related Findings Section */}
            {relatedFindings && relatedFindings.length > 0 && (
              <Card>
                <CardContent className="flex flex-col gap-3 p-4">
                  <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
                    Related Findings
                  </h3>
                  <div className="text-xs text-gray-600 dark:text-gray-400">
                    {relatedFindings.length} finding(s)
                  </div>
                  <NodeRemediation findings={relatedFindings} />
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
};
