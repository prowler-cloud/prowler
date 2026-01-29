"use client";

import { Button, Card, CardContent } from "@/components/shadcn";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet/sheet";
import type { GraphNode } from "@/types/attack-paths";

import { NodeFindings } from "./node-findings";
import { NodeOverview } from "./node-overview";
import { NodeResources } from "./node-resources";

interface NodeDetailPanelProps {
  node: GraphNode | null;
  allNodes?: GraphNode[];
  onClose?: () => void;
}

/**
 * Node details content component (reusable)
 */
export const NodeDetailContent = ({
  node,
  allNodes = [],
}: {
  node: GraphNode;
  allNodes?: GraphNode[];
}) => {
  const isProwlerFinding = node?.labels.some((label) =>
    label.toLowerCase().includes("finding"),
  );

  return (
    <div className="flex flex-col gap-6">
      {/* Node Overview Section */}
      <Card className="border-border-neutral-secondary">
        <CardContent className="flex flex-col gap-3 p-4">
          <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
            Node Overview
          </h3>
          <NodeOverview node={node} />
        </CardContent>
      </Card>

      {/* Related Findings Section - Only show for non-Finding nodes */}
      {!isProwlerFinding && (
        <Card className="border-border-neutral-secondary">
          <CardContent className="flex flex-col gap-3 p-4">
            <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
              Related Findings
            </h3>
            <div className="text-text-neutral-secondary dark:text-text-neutral-secondary text-xs">
              Findings connected to this node
            </div>
            <NodeFindings node={node} allNodes={allNodes} />
          </CardContent>
        </Card>
      )}

      {/* Affected Resources Section - Only show for Finding nodes */}
      {isProwlerFinding && (
        <Card className="border-border-neutral-secondary">
          <CardContent className="flex flex-col gap-3 p-4">
            <h3 className="dark:text-prowler-theme-pale/90 text-sm font-semibold">
              Affected Resources
            </h3>
            <div className="text-text-neutral-secondary dark:text-text-neutral-secondary text-xs">
              Resources affected by this finding
            </div>
            <NodeResources node={node} allNodes={allNodes} />
          </CardContent>
        </Card>
      )}
    </div>
  );
};

/**
 * Right-side sheet panel for node details
 * Shows comprehensive information about selected graph node
 * Uses shadcn Sheet component for sliding panel from right
 */
export const NodeDetailPanel = ({
  node,
  allNodes = [],
  onClose,
}: NodeDetailPanelProps) => {
  const isOpen = node !== null;

  const isProwlerFinding = node?.labels.some((label) =>
    label.toLowerCase().includes("finding"),
  );

  return (
    <Sheet open={isOpen} onOpenChange={(open) => !open && onClose?.()}>
      <SheetContent className="dark:bg-prowler-theme-midnight my-4 max-h-[calc(100vh-2rem)] max-w-[95vw] overflow-y-auto rounded-l-xl pt-10 md:my-8 md:max-h-[calc(100vh-4rem)] md:max-w-[55vw]">
        <SheetHeader>
          <div className="flex items-start justify-between gap-2">
            <div className="flex-1">
              <SheetTitle>Node Details</SheetTitle>
              <SheetDescription>
                {String(node?.properties?.name || node?.id.substring(0, 20))}
              </SheetDescription>
            </div>
            {node && isProwlerFinding && (
              <Button asChild variant="default" size="sm" className="mt-1">
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
          </div>
        </SheetHeader>

        {node && (
          <div className="pt-6">
            <NodeDetailContent node={node} allNodes={allNodes} />
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
};
