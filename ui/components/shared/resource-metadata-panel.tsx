"use client";

import { Card } from "@/components/shadcn/card/card";
import {
  QUERY_EDITOR_LANGUAGE,
  QueryCodeEditor,
} from "@/components/shared/query-code-editor";
import { parseMetadata } from "@/lib/resource-metadata";

interface ResourceMetadataPanelProps {
  metadata: Record<string, unknown> | string | null | undefined;
  details: string | null | undefined;
}

/**
 * Shared "Metadata" panel for a resource.
 *
 * Renders the resource `details` text and its `metadata` as formatted JSON
 * with a copy-to-clipboard action, falling back to an empty state when
 * neither is available. Reused by the resource detail view and the finding
 * detail drawer (compliance requirement findings view) to keep the UX
 * consistent across surfaces.
 */
export function ResourceMetadataPanel({
  metadata,
  details,
}: ResourceMetadataPanelProps) {
  const parsedMetadata = parseMetadata(metadata);
  const hasMetadata =
    parsedMetadata !== null && Object.keys(parsedMetadata).length > 0;
  const hasDetails = Boolean(details?.trim());
  const formattedMetadata =
    hasMetadata && parsedMetadata
      ? JSON.stringify(parsedMetadata, null, 2)
      : null;

  return (
    <>
      {hasDetails && (
        <Card variant="inner">
          <div className="flex flex-col gap-1">
            <span className="text-text-neutral-secondary text-sm font-semibold">
              Details:
            </span>
            <p className="text-text-neutral-primary text-sm break-words whitespace-pre-wrap">
              {details}
            </p>
          </div>
        </Card>
      )}

      {formattedMetadata && (
        <QueryCodeEditor
          ariaLabel="Resource metadata"
          visibleLabel={null}
          language={QUERY_EDITOR_LANGUAGE.JSON}
          value={formattedMetadata}
          copyValue={formattedMetadata}
          editable={false}
          minHeight={220}
          fill
          showCopyButton
          onChange={() => {}}
        />
      )}

      {!hasDetails && !hasMetadata && (
        <p className="text-text-neutral-tertiary py-8 text-center text-sm">
          No metadata available for this resource.
        </p>
      )}
    </>
  );
}
