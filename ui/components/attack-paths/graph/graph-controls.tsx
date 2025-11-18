"use client";

import { Download, Maximize2, ZoomIn, ZoomOut, Minimize2 } from "lucide-react";

import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip/tooltip";

interface GraphControlsProps {
  onZoomIn: () => void;
  onZoomOut: () => void;
  onFitToScreen: () => void;
  onExport: () => void;
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
    <div className="mb-4 flex items-center justify-end">
      <div className="flex gap-1 rounded-lg border border-border-neutral-primary bg-bg-neutral-tertiary p-1">
        <TooltipProvider>
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="ghost"
                size="sm"
                onClick={onZoomIn}
                className="h-8 w-8 p-0"
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
                className="h-8 w-8 p-0"
              >
                <Download size={18} />
              </Button>
            </TooltipTrigger>
            <TooltipContent>Export graph</TooltipContent>
          </Tooltip>
        </TooltipProvider>
      </div>
    </div>
  );
};
