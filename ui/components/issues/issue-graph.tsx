"use client";

import { useEffect, useRef, useState } from "react";

import { getFindings } from "@/actions/findings";
import { AttackPathGraph } from "@/components/attack-paths/graph/attack-path-graph";
import { FindingDetailDrawer } from "@/components/findings/table";
import {
  buildIssueGraph,
  GRAPH_RESOURCE_LIMIT,
} from "@/components/issues/issue-graph.adapter";
import { Alert, AlertDescription } from "@/components/shadcn/alert";
import { Card } from "@/components/shadcn/card/card";
import { useFindingDetails } from "@/hooks/use-finding-details";
import { isProwlerFindingNode } from "@/lib/attack-paths/node-types";
import { GraphNode } from "@/types/attack-paths";
import { IssueAttributes, IssueFinding } from "@/types/issues";

interface IssueGraphBaseProps {
  issue: IssueAttributes;
  resourceUids: string[];
  findings?: IssueFinding[];
}

interface ScopedIssueGraphProps extends IssueGraphBaseProps {
  providerId: string;
  scanId: string;
}

interface UnscopedIssueGraphProps extends IssueGraphBaseProps {
  providerId?: never;
  scanId?: never;
}

type IssueGraphProps = ScopedIssueGraphProps | UnscopedIssueGraphProps;

export const IssueGraph = ({
  issue,
  resourceUids,
  findings = [],
  providerId,
  scanId,
}: IssueGraphProps) => {
  const finding = useFindingDetails();
  const view = buildIssueGraph(issue, resourceUids, findings);
  const shownFindings = new Set(
    view.nodes.flatMap((node) =>
      node.properties.finding_id ? [String(node.properties.finding_id)] : [],
    ),
  ).size;
  const pending = useRef(false);
  const mounted = useRef(true);
  const [loading, setLoading] = useState(false);
  const [lookupComplete, setLookupComplete] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const expandedResources = new Set(
    view.nodes
      .filter((node) => node.id.startsWith("resource:"))
      .map((node) => node.id),
  );

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const handleNodeClick = async (node: GraphNode) => {
    if (!isProwlerFindingNode(node.labels) || pending.current) return;
    setError(null);
    setLookupComplete(false);
    finding.resetFindingDetails();
    let findingId = node.properties.finding_id;
    if (!findingId && (!providerId || !scanId)) {
      setError(
        "Finding details are unavailable because this issue has no provider or scan reference.",
      );
      return;
    }
    pending.current = true;
    setLoading(true);
    try {
      if (!findingId) {
        const response = await getFindings({
          pageSize: 1,
          filters: {
            "filter[provider_id]": providerId,
            "filter[scan]": scanId,
            "filter[check_id]": String(node.properties.check_id),
            "filter[resource_uid]": String(node.properties.resource_uid),
            "filter[status]": "FAIL",
          },
        });
        if (!mounted.current) return;
        if (!Array.isArray(response?.data)) {
          setError("Could not load this finding. Select the finding to retry.");
          return;
        }
        const match = response.data[0];
        // Reject mismatched responses even though the lookup is scoped to the scan.
        if (!match || match.relationships?.scan?.data?.id !== scanId) {
          setError(
            "This finding is no longer available for the issue's scan. Refresh issues to load the latest assessment.",
          );
          return;
        }
        findingId = match.id;
      }
      await finding.navigateToFinding(String(findingId));
      if (mounted.current) setLookupComplete(true);
    } catch {
      if (mounted.current)
        setError("Could not load this finding. Select the finding to retry.");
    } finally {
      pending.current = false;
      if (mounted.current) setLoading(false);
    }
  };
  const detailFailed =
    lookupComplete && !finding.findingDetailLoading && !finding.findingDetails;

  return (
    <section
      aria-label="Finding evidence"
      className="flex min-w-0 flex-col gap-3"
    >
      <h4 className="text-sm font-semibold">Finding evidence</h4>
      <p className="text-text-neutral-tertiary text-sm">
        Showing {shownFindings} of {issue.findings_count} issue findings across{" "}
        {Math.min(resourceUids.length, GRAPH_RESOURCE_LIMIT)} of{" "}
        {resourceUids.length} affected resources, plus supporting checks cited
        by the assessment. These links show evidence associations, not confirmed
        attack paths.
      </p>
      {loading && (
        <p role="status" className="text-sm">
          Loading finding details…
        </p>
      )}
      {(error || detailFailed) && (
        <Alert variant="error">
          <AlertDescription>
            {error ??
              "Could not load this finding. Select the finding to retry."}
          </AlertDescription>
        </Alert>
      )}
      <Card
        variant="inner"
        padding="none"
        className="h-[420px] overflow-hidden"
      >
        <AttackPathGraph
          data={{ nodes: view.nodes, edges: view.edges }}
          view={view}
          expandedResources={expandedResources}
          onNodeClick={handleNodeClick}
        />
      </Card>
      {finding.findingDetails && (
        <FindingDetailDrawer
          key={finding.findingDetails.id}
          finding={finding.findingDetails}
          defaultOpen
          onOpenChange={(open) => {
            if (!open) {
              setLookupComplete(false);
              finding.resetFindingDetails();
            }
          }}
        />
      )}
    </section>
  );
};
