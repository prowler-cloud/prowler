"use client";

import {
  ChevronFirst,
  ChevronLast,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";

import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/shadcn/select/select";
import { cn } from "@/lib/utils";

const NAV_BUTTON_STYLES = {
  base: "flex items-center justify-center rounded-full p-3 transition-colors",
  enabled:
    "text-text-neutral-secondary hover:text-white cursor-pointer focus:outline-none",
  disabled: "text-text-neutral-tertiary cursor-not-allowed pointer-events-none",
} as const;

interface ClientSidePaginationProps {
  currentPage: number;
  totalPages: number;
  pageSize: number;
  onPageChange: (page: number) => void;
  onPageSizeChange: (size: number) => void;
}

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100] as const;

export function DataTableClientPagination({
  currentPage,
  totalPages,
  pageSize,
  onPageChange,
  onPageSizeChange,
}: ClientSidePaginationProps) {
  const isFirstPage = currentPage === 1;
  const isLastPage = currentPage === totalPages;

  return (
    <div className="flex w-full items-center justify-end gap-6 py-1.5">
      {/* Rows per page selector */}
      <div className="flex items-center gap-3">
        <span className="text-text-neutral-secondary text-xs font-medium whitespace-nowrap">
          Rows per page
        </span>
        <Select
          value={String(pageSize)}
          onValueChange={(value) => onPageSizeChange(Number(value))}
        >
          <SelectTrigger
            iconSize="sm"
            className="bg-bg-neutral-tertiary border-border-neutral-tertiary !h-auto !w-auto !min-w-0 !gap-1 !rounded-full !px-[19px] !py-[9px] !text-xs !font-medium backdrop-blur-[46px]"
          >
            <SelectValue />
          </SelectTrigger>
          <SelectContent side="top">
            {PAGE_SIZE_OPTIONS.map((size) => (
              <SelectItem
                key={size}
                value={String(size)}
                className="cursor-pointer"
              >
                {size}
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
          <button
            aria-label="Go to first page"
            className={cn(
              NAV_BUTTON_STYLES.base,
              isFirstPage
                ? NAV_BUTTON_STYLES.disabled
                : NAV_BUTTON_STYLES.enabled,
            )}
            onClick={() => onPageChange(1)}
            disabled={isFirstPage}
          >
            <ChevronFirst className="size-6" aria-hidden="true" />
          </button>
          <button
            aria-label="Go to previous page"
            className={cn(
              NAV_BUTTON_STYLES.base,
              isFirstPage
                ? NAV_BUTTON_STYLES.disabled
                : NAV_BUTTON_STYLES.enabled,
            )}
            onClick={() => onPageChange(currentPage - 1)}
            disabled={isFirstPage}
          >
            <ChevronLeft className="size-6" aria-hidden="true" />
          </button>
          <button
            aria-label="Go to next page"
            className={cn(
              NAV_BUTTON_STYLES.base,
              isLastPage
                ? NAV_BUTTON_STYLES.disabled
                : NAV_BUTTON_STYLES.enabled,
            )}
            onClick={() => onPageChange(currentPage + 1)}
            disabled={isLastPage}
          >
            <ChevronRight className="size-6" aria-hidden="true" />
          </button>
          <button
            aria-label="Go to last page"
            className={cn(
              NAV_BUTTON_STYLES.base,
              isLastPage
                ? NAV_BUTTON_STYLES.disabled
                : NAV_BUTTON_STYLES.enabled,
            )}
            onClick={() => onPageChange(totalPages)}
            disabled={isLastPage}
          >
            <ChevronLast className="size-6" aria-hidden="true" />
          </button>
        </div>
      </div>
    </div>
  );
}
