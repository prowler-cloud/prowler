"use client";

import Link from "next/link";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import { CodeSnippet } from "@/components/shadcn/code-snippet";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/shadcn/table/table";

const RESOURCE_PAGE_SIZE = 12;

// The issue carries resource uids, not ids, so this opens the Resources list
// on that one resource rather than its drawer.
const resourceHref = (uid: string, providerId?: string) =>
  `/resources?${new URLSearchParams({
    "filter[uid]": uid,
    // A uid is unique within an account, not across them.
    ...(providerId && { "filter[provider_id__in]": providerId }),
  })}`;

interface IssueResourcesProps {
  resources: string[];
  providerId?: string;
}

/** The resources the issue folds, a page at a time, as a table. */
export const IssueResources = ({
  resources,
  providerId,
}: IssueResourcesProps) => {
  const [visible, setVisible] = useState(RESOURCE_PAGE_SIZE);

  if (resources.length === 0) {
    return (
      <p className="text-text-neutral-tertiary text-sm">
        This issue has no affected resources.
      </p>
    );
  }

  return (
    <section aria-label="Affected resources" className="flex flex-col gap-2">
      <div className="flex items-center justify-end">
        <span className="text-text-neutral-tertiary text-sm">
          {resources.length.toLocaleString()} Total Entries
        </span>
      </div>
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead>
              <span className="text-text-neutral-secondary text-sm font-medium">
                Resource
              </span>
            </TableHead>
            <TableHead className="w-10" />
          </TableRow>
        </TableHeader>
        <TableBody>
          {resources.slice(0, visible).map((uid) => (
            <TableRow key={uid}>
              <TableCell className="max-w-0">
                <CodeSnippet value={uid} ariaLabel={`Copy ${uid}`} />
              </TableCell>
              <TableCell className="text-right whitespace-nowrap">
                <Button asChild variant="link" size="link-sm">
                  <Link
                    href={resourceHref(uid, providerId)}
                    aria-label={`Open in Resources: ${uid}`}
                  >
                    Open in Resources
                  </Link>
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>
      <div className="flex flex-wrap items-center gap-3">
        {visible < resources.length && (
          <Button
            variant="link"
            size="link-sm"
            onClick={() => setVisible((value) => value + RESOURCE_PAGE_SIZE)}
          >
            Show more resources
          </Button>
        )}
        {visible > RESOURCE_PAGE_SIZE && (
          <Button
            variant="link"
            size="link-sm"
            onClick={() => setVisible(RESOURCE_PAGE_SIZE)}
          >
            Show fewer resources
          </Button>
        )}
      </div>
    </section>
  );
};
