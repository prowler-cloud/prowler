"use client";

import { Download, Minimize2, ZoomIn, ZoomOut } from "lucide-react";

import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

interface GraphControlsProps {
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitToScreen: () => void;
  onExport?: () => void;
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
}: GraphControlsProps) => {
  return (
    <div className="flex items-center">
      <div className="border-border-neutral-primary bg-bg-neutral-tertiary flex gap-1 rounded-lg border p-1">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                onClick={onZoomIn}
                className="h-8 w-8 p-0"
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
                size="sm"
                onClick={onZoomOut}
                className="h-8 w-8 p-0"
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
                size="sm"
                onClick={onFitToScreen}
                className="h-8 w-8 p-0"
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
                size="sm"
                onClick={onExport}
                disabled={!onExport}
                className="h-8 w-8 p-0"
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
