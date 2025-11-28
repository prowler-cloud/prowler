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
