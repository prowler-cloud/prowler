"use client";

import {
  ChevronFirst,
  ChevronLast,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { getPaginationInfo } from "@/lib";
import { cn } from "@/lib/utils";
import { MetaDataProps } from "@/types";

interface DataTablePaginationProps {
  metadata?: MetaDataProps;
  disableScroll?: boolean;
  /** Prefix for URL params to avoid conflicts (e.g., "findings" -> "findingsPage") */
  paramPrefix?: string;

  /*
   * Controlled mode: Use these props to manage pagination via React state
   * instead of URL params. Useful for tables in drawers/modals to avoid
   * triggering page re-renders when paginating.
   */
  controlledPage?: number;
  controlledPageSize?: number;
  onPageChange?: (page: number) => void;
  onPageSizeChange?: (pageSize: number) => void;
}

const NAV_BUTTON_STYLES = {
  base: "flex items-center justify-center rounded-full p-3 transition-colors",
  enabled: "text-text-neutral-secondary hover:text-white",
  disabled: "text-text-neutral-tertiary cursor-not-allowed pointer-events-none",
} as const;

export function DataTablePagination({
  metadata,
  disableScroll = false,
  paramPrefix = "",
  controlledPage,
  controlledPageSize,
  onPageChange,
  onPageSizeChange,
}: DataTablePaginationProps) {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const router = useRouter();

  // Determine if we're in controlled mode
  const isControlled = controlledPage !== undefined && onPageChange;

  // Determine param names based on prefix
  const pageParam = paramPrefix ? `${paramPrefix}Page` : "page";
  const pageSizeParam = paramPrefix ? `${paramPrefix}PageSize` : "pageSize";

  const initialPageSize = isControlled
    ? String(controlledPageSize ?? 10)
    : (searchParams.get(pageSizeParam) ?? "10");

  const [selectedPageSize, setSelectedPageSize] = useState(initialPageSize);

  if (!metadata) return null;

  const {
    currentPage: metaCurrentPage,
    totalPages,
    totalEntries,
    itemsPerPageOptions,
  } = getPaginationInfo(metadata);

  // For controlled mode, use controlled values; for prefixed, read from URL; otherwise use metadata
  const currentPage = isControlled
    ? controlledPage
    : paramPrefix
      ? parseInt(searchParams.get(pageParam) || "1", 10)
      : metaCurrentPage;

  const createPageUrl = (pageNumber: number | string) => {
    const params = new URLSearchParams(searchParams);

    // Preserve all important parameters
    const scanId = searchParams.get("scanId");
    const id = searchParams.get("id");
    const version = searchParams.get("version");

    if (+pageNumber > totalPages) {
      return `${pathname}?${params.toString()}`;
    }

    params.set(pageParam, pageNumber.toString());

    // Ensure that scanId, id and version are preserved
    if (scanId) params.set("scanId", scanId);
    if (id) params.set("id", id);
    if (version) params.set("version", version);

    return `${pathname}?${params.toString()}`;
  };

  // Handle page navigation for controlled mode
  const handlePageChange = (pageNumber: number) => {
    if (isControlled) {
      onPageChange(pageNumber);
    } else {
      const url = createPageUrl(pageNumber);
      if (disableScroll) {
        router.push(url, { scroll: false });
      } else {
        router.push(url);
      }
    }
  };

  const isFirstPage = currentPage === 1;
  const isLastPage = currentPage === totalPages;

  return (
    <div className="flex w-full items-center justify-end gap-6 py-1.5">
      {totalEntries > 10 && (
        <>
          {/* Rows per page selector */}
          <div className="flex items-center gap-3">
            <span className="text-text-neutral-secondary text-xs font-medium whitespace-nowrap">
              Rows per page
            </span>
            <Select
              value={selectedPageSize}
              onValueChange={(value) => {
                setSelectedPageSize(value);

                if (isControlled) {
                  onPageSizeChange?.(parseInt(value, 10));
                  onPageChange(1); // Reset to first page
                  return;
                }

                const params = new URLSearchParams(searchParams);

                // Preserve all important parameters
                const scanId = searchParams.get("scanId");
                const id = searchParams.get("id");
                const version = searchParams.get("version");

                params.set(pageSizeParam, value);
                params.set(pageParam, "1");

                // Ensure that scanId, id and version are preserved
                if (scanId) params.set("scanId", scanId);
                if (id) params.set("id", id);
                if (version) params.set("version", version);

                // This pushes the URL without reloading the page
                if (disableScroll) {
                  const url = `${pathname}?${params.toString()}`;
                  router.push(url, { scroll: false });
                } else {
                  router.push(`${pathname}?${params.toString()}`);
                }
              }}
            >
              <SelectTrigger
                iconSize="sm"
                className="bg-bg-neutral-tertiary border-border-neutral-tertiary !h-auto !w-auto !min-w-0 !gap-1 !rounded-full !px-[19px] !py-[9px] !text-xs !font-medium backdrop-blur-[46px]"
              >
                <SelectValue />
              </SelectTrigger>
              <SelectContent side="top">
                {itemsPerPageOptions.map((pageSize) => (
                  <SelectItem
                    key={pageSize}
                    value={`${pageSize}`}
                    className="cursor-pointer"
                  >
                    {pageSize}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Page info and navigation */}
          <div className="flex items-center gap-3">
            <span className="text-text-neutral-secondary text-xs font-medium">
              Page {currentPage} of {totalPages}
            </span>
            <div className="flex items-center gap-3">
              {isControlled ? (
                <>
                  <button
                    type="button"
                    aria-label="Go to first page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isFirstPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    disabled={isFirstPage}
                    onClick={() => handlePageChange(1)}
                  >
                    <ChevronFirst className="size-6" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label="Go to previous page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isFirstPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    disabled={isFirstPage}
                    onClick={() => handlePageChange(currentPage - 1)}
                  >
                    <ChevronLeft className="size-6" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label="Go to next page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isLastPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    disabled={isLastPage}
                    onClick={() => handlePageChange(currentPage + 1)}
                  >
                    <ChevronRight className="size-6" aria-hidden="true" />
                  </button>
                  <button
                    type="button"
                    aria-label="Go to last page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isLastPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    disabled={isLastPage}
                    onClick={() => handlePageChange(totalPages)}
                  >
                    <ChevronLast className="size-6" aria-hidden="true" />
                  </button>
                </>
              ) : (
                <>
                  <Link
                    aria-label="Go to first page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isFirstPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    href={
                      isFirstPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(1)
                    }
                    scroll={!disableScroll}
                    aria-disabled={isFirstPage}
                    onClick={(e) => isFirstPage && e.preventDefault()}
                  >
                    <ChevronFirst className="size-6" aria-hidden="true" />
                  </Link>
                  <Link
                    aria-label="Go to previous page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isFirstPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    href={
                      isFirstPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(currentPage - 1)
                    }
                    scroll={!disableScroll}
                    aria-disabled={isFirstPage}
                    onClick={(e) => isFirstPage && e.preventDefault()}
                  >
                    <ChevronLeft className="size-6" aria-hidden="true" />
                  </Link>
                  <Link
                    aria-label="Go to next page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isLastPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    href={
                      isLastPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(currentPage + 1)
                    }
                    scroll={!disableScroll}
                    aria-disabled={isLastPage}
                    onClick={(e) => isLastPage && e.preventDefault()}
                  >
                    <ChevronRight className="size-6" aria-hidden="true" />
                  </Link>
                  <Link
                    aria-label="Go to last page"
                    className={cn(
                      NAV_BUTTON_STYLES.base,
                      isLastPage
                        ? NAV_BUTTON_STYLES.disabled
                        : NAV_BUTTON_STYLES.enabled,
                    )}
                    href={
                      isLastPage
                        ? pathname + "?" + searchParams.toString()
                        : createPageUrl(totalPages)
                    }
                    scroll={!disableScroll}
                    aria-disabled={isLastPage}
                    onClick={(e) => isLastPage && e.preventDefault()}
                  >
                    <ChevronLast className="size-6" aria-hidden="true" />
                  </Link>
                </>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
