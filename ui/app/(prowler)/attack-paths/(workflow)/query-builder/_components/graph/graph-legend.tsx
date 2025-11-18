"use client";

import { Card, CardContent } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipProvider,
  TooltipTrigger,
} from "@/components/ui/tooltip/tooltip";

import { GRAPH_NODE_COLORS } from "../../_lib/graph-colors";

interface LegendItem {
  label: string;
  color: string;
  description: string;
}

const legendItems: LegendItem[] = [
  {
    label: "Prowler Finding",
    color: GRAPH_NODE_COLORS.prowlerFinding,
    description: "Security findings from Prowler scans",
  },
  {
    label: "AWS Account",
    color: GRAPH_NODE_COLORS.awsAccount,
    description: "AWS account root node",
  },
  {
    label: "EC2 Instance",
    color: GRAPH_NODE_COLORS.ec2Instance,
    description: "Elastic Compute Cloud instance",
  },
  {
    label: "S3 Bucket",
    color: GRAPH_NODE_COLORS.s3Bucket,
    description: "Simple Storage Service bucket",
  },
  {
    label: "IAM Role",
    color: GRAPH_NODE_COLORS.iamRole,
    description: "Identity and Access Management role",
  },
  {
    label: "Other Resource",
    color: GRAPH_NODE_COLORS.default,
    description: "Other AWS resource types",
  },
];

/**
 * Legend for attack path graph node types
 * Shows available node types and their meanings
 */
export const GraphLegend = () => {
  return (
    <Card className="w-fit border-0">
      <CardContent className="gap-3 p-4">
        <div className="flex flex-col items-center gap-4 lg:flex-row lg:flex-wrap">
          <TooltipProvider>
            {legendItems.map((item) => (
              <Tooltip key={item.label}>
                <TooltipTrigger asChild>
                  <div
                    className="flex cursor-help items-center gap-2"
                    role="img"
                    aria-label={`${item.label}: ${item.description}`}
                  >
                    <div
                      className="h-4 w-4 rounded-full"
                      style={{ backgroundColor: item.color, opacity: 0.8 }}
                      aria-hidden="true"
                    />
                    <span className="text-text-neutral-secondary dark:text-text-neutral-secondary text-xs">
                      {item.label}
                    </span>
                  </div>
                </TooltipTrigger>
                <TooltipContent>{item.description}</TooltipContent>
              </Tooltip>
            ))}
          </TooltipProvider>
        </div>
      </CardContent>
    </Card>
  );
};
