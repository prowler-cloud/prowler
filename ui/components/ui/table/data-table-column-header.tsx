"use client";

import { Button } from "@nextui-org/react";
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
      return <ChevronsLeftRightIcon size={14} className="ml-2 rotate-90" />;
    }
    return currentSortParam === `-${param}` ? (
      <ArrowDownIcon size={12} className="ml-2" />
    ) : (
      <ArrowUpIcon size={12} className="ml-2" />
    );
  };

  if (!column.getCanSort()) {
    return <div>{title}</div>;
  }

  return (
    <Button
      className="h-10 w-fit max-w-[110px] whitespace-nowrap bg-transparent px-0 text-left align-middle text-tiny font-semibold text-foreground-500 outline-none dark:text-slate-400"
      onClick={getToggleSortingHandler}
    >
      <span
        className="block whitespace-normal break-normal"
        style={{
          display: "-webkit-box",
          WebkitBoxOrient: "vertical",
          WebkitLineClamp: 2,
          width: "90px",
        }}
      >
        {title}
      </span>
      {renderSortIcon()}
    </Button>
  );
};
