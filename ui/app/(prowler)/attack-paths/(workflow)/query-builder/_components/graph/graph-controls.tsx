"use client";

import {
  ChevronsDownUp,
  Download,
  Minimize2,
  ZoomIn,
  ZoomOut,
} from "lucide-react";

import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

// Collapse-all is all-or-nothing: the enabled flag and its handler always
// travel together, so a button can never be enabled without something to do.
interface GraphCollapseAll {
  can: boolean;
  onCollapse: () => void;
}

interface GraphControlsProps {
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitToScreen: () => void;
  onExport?: () => void;
  // Collapse every expanded resource-class group. Omitted where unsupported;
  // the button hides itself while nothing is expanded.
  collapseAll?: GraphCollapseAll;
}

/**
 * Controls for graph visualization (zoom, pan, export)
 * Positioned as floating toolbar above graph
 */
export const GraphControls = ({
  onZoomIn,
  onZoomOut,
  onFitToScreen,
  onExport,
  collapseAll,
}: GraphControlsProps) => {
  return (
    <div className="flex items-center">
      <div className="border-border-neutral-primary bg-bg-neutral-tertiary flex gap-1 rounded-lg border p-1">
        <TooltipProvider>
          {collapseAll?.can && (
            <Tooltip>
              <TooltipTrigger asChild>
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={collapseAll.onCollapse}
                  aria-label="Collapse all groups"
                >
                  <ChevronsDownUp size={18} />
                </Button>
              </TooltipTrigger>
              <TooltipContent>Collapse all groups</TooltipContent>
            </Tooltip>
          )}

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onZoomIn}
                aria-label="Zoom in"
              >
                <ZoomIn size={18} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Zoom in</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onZoomOut}
                aria-label="Zoom out"
              >
                <ZoomOut size={18} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Zoom out</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onFitToScreen}
                aria-label="Fit graph to view"
              >
                <Minimize2 size={18} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Fit graph to view</TooltipContent>
          </Tooltip>

          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="icon-sm"
                onClick={onExport}
                disabled={!onExport}
                aria-label={onExport ? "Export graph" : "Export available soon"}
              >
                <Download size={18} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              {onExport ? "Export graph" : "Export available soon"}
            </TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    </div>
  );
};
