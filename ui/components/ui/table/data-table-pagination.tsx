"use client";

import {
  ChevronLeftIcon,
  ChevronRightIcon,
  DoubleArrowLeftIcon,
  DoubleArrowRightIcon,
} from "@radix-ui/react-icons";
import Link from "next/link";
import { usePathname, useSearchParams } from "next/navigation";

import { getPaginationInfo } from "@/lib";
import { MetaDataProps } from "@/types";

interface DataTablePaginationProps {
  pageSizeOptions?: number[];
  metadata?: MetaDataProps;
}

export function DataTablePagination({ metadata }: DataTablePaginationProps) {
  if (!metadata) return null;
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const { currentPage, totalPages, totalEntries } = getPaginationInfo(metadata);

  const createPageUrl = (pageNumber: number | string) => {
    const params = new URLSearchParams(searchParams);

    if (pageNumber === "...") return `${pathname}?${params.toString()}`;

    if (+pageNumber > totalPages) {
      return `${pathname}?${params.toString()}`;
    }

    params.set("page", pageNumber.toString());
    return `${pathname}?${params.toString()}`;
  };

  return (
    <div className="flex w-full flex-col-reverse items-center justify-between gap-4 overflow-auto p-1 sm:flex-row sm:gap-8">
      <div className="whitespace-nowrap text-sm font-medium">
        {totalEntries} entries in Total.
      </div>
      <div className="flex flex-col-reverse items-center gap-4 sm:flex-row sm:gap-6 lg:gap-8">
        <div className="flex items-center justify-center text-sm font-medium">
          Page {currentPage} of {totalPages}
        </div>
        <div className="flex items-center space-x-2">
          <Link
            aria-label="Go to first page"
            className="page-link relative block rounded border-0 bg-transparent px-3 py-1.5 text-gray-800 outline-none transition-all duration-300 hover:bg-gray-200 hover:text-gray-800 focus:shadow-none dark:text-prowler-theme-green"
            href={createPageUrl(1)}
            aria-disabled="true"
          >
            <DoubleArrowLeftIcon className="size-4" aria-hidden="true" />
          </Link>
          <Link
            aria-label="Go to previous page"
            className="page-link relative block rounded border-0 bg-transparent px-3 py-1.5 text-gray-800 outline-none transition-all duration-300 hover:bg-gray-200 hover:text-gray-800 focus:shadow-none dark:text-prowler-theme-green"
            href={createPageUrl(currentPage - 1)}
            aria-disabled="true"
          >
            <ChevronLeftIcon className="size-4" aria-hidden="true" />
          </Link>
          <Link
            aria-label="Go to next page"
            className="page-link relative block rounded border-0 bg-transparent px-3 py-1.5 text-gray-800 outline-none transition-all duration-300 hover:bg-gray-200 hover:text-gray-800 focus:shadow-none dark:text-prowler-theme-green"
            href={createPageUrl(currentPage + 1)}
          >
            <ChevronRightIcon className="size-4" aria-hidden="true" />
          </Link>
          <Link
            aria-label="Go to last page"
            className="page-link relative block rounded border-0 bg-transparent px-3 py-1.5 text-gray-800 outline-none transition-all duration-300 hover:bg-gray-200 hover:text-gray-800 focus:shadow-none dark:text-prowler-theme-green"
            href={createPageUrl(totalPages)}
          >
            <DoubleArrowRightIcon className="size-4" aria-hidden="true" />
          </Link>
        </div>
      </div>
    </div>
  );
}
