"use client";

import { Button } from "@nextui-org/react";
import { Column } from "@tanstack/react-table";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  ChevronsLeftRightIcon,
} from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { HTMLAttributes } from "react";

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
      return <ChevronsLeftRightIcon className="ml-2 h-4 w-4 rotate-90" />;
    }
    return currentSortParam === `-${param}` ? (
      <ArrowDownIcon className="ml-2 h-4 w-4" />
    ) : (
      <ArrowUpIcon className="ml-2 h-4 w-4" />
    );
  };

  if (!column.getCanSort()) {
    return <div>{title}</div>;
  }

  return (
    <Button
      variant="light"
      size="md"
      className="text-slate-500 dark:text-slate-400 h-8"
      onClick={getToggleSortingHandler}
    >
      <span>{title}</span>
      {renderSortIcon()}
    </Button>
  );
};
