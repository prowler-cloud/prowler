"use client";

import { Column } from "@tanstack/react-table";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { HTMLAttributes } from "react";

import {
  ArrowDownIcon,
  ArrowUpIcon,
  ChevronsLeftRightIcon,
} from "@/components/icons";

interface DataTableColumnHeaderProps<TData, TValue>
  extends HTMLAttributes<HTMLDivElement> {
  column: Column<TData, TValue>;
  title: string;
  param?: string;
}

export const DataTableColumnHeader = <TData, TValue>({
  column,
  title,
  param,
}: DataTableColumnHeaderProps<TData, TValue>) => {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const getToggleSortingHandler = () => {
    const currentParams = new URLSearchParams(searchParams.toString());
    const currentSortParam = currentParams.get("sort");
    let newSortParam = "";

    if (currentSortParam === `${param}`) {
      // If already sorting ascending, switch to descending
      newSortParam = `-${param}`;
    } else if (currentSortParam === `-${param}`) {
      // If already sorting descending, remove sorting
      newSortParam = "";
    } else {
      // Sort ascending for the first time or switch to a different column
      newSortParam = `${param}`;
    }

    // Update or remove the sort parameter
    if (newSortParam) {
      currentParams.set("sort", newSortParam);
    } else {
      currentParams.delete("sort");
    }

    // Construct the new URL with all parameters
    const newUrl = `${pathname}?${currentParams.toString()}`;

    router.push(newUrl, {
      scroll: false,
    });
  };

  const renderSortIcon = () => {
    const currentSortParam = searchParams.get("sort");
    if (
      !currentSortParam ||
      currentSortParam === "" ||
      (currentSortParam !== param && currentSortParam !== `-${param}`)
    ) {
      return <ChevronsLeftRightIcon size={14} className="ml-1 rotate-90" />;
    }
    return currentSortParam === `-${param}` ? (
      <ArrowDownIcon size={12} className="ml-1" />
    ) : (
      <ArrowUpIcon size={12} className="ml-1" />
    );
  };

  const baseClassName =
    "text-text-neutral-primary flex h-8 items-center text-left align-middle text-sm font-semibold whitespace-nowrap outline-none -ml-px";

  if (!column.getCanSort()) {
    return (
      <div className={baseClassName}>
        <span className="block break-normal whitespace-nowrap">{title}</span>
      </div>
    );
  }

  return (
    <button
      type="button"
      className={`${baseClassName} hover:text-text-neutral-tertiary cursor-pointer`}
      onClick={getToggleSortingHandler}
    >
      <span className="block break-normal whitespace-nowrap">{title}</span>
      {renderSortIcon()}
    </button>
  );
};
