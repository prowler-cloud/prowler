import { Button } from "@nextui-org/react";
import { Column } from "@tanstack/react-table";
import {
  ArrowDownIcon,
  ArrowUpIcon,
  ChevronsLeftRightIcon,
} from "lucide-react";
import { HTMLAttributes } from "react";

interface DataTableColumnHeaderProps<TData, TValue>
  extends HTMLAttributes<HTMLDivElement> {
  column: Column<TData, TValue>;
  title: string;
}

export const DataTableColumnHeader = <TData, TValue>({
  column,
  title,
  className,
}: DataTableColumnHeaderProps<TData, TValue>) => {
  const renderSortIcon = () => {
    const sort = column.getIsSorted();
    if (!sort) {
      return <ChevronsLeftRightIcon className="ml-2 h-4 w-4 rotate-90" />;
    }
    return sort === "desc" ? (
      <ArrowDownIcon className="ml-2 h-4 w-4" />
    ) : (
      <ArrowUpIcon className="ml-2 h-4 w-4" />
    );
  };

  if (!column.getCanSort()) {
    return <div className={className}>{title}</div>;
  }
  return (
    <div className={className}>
      <Button
        variant="ghost"
        size="sm"
        className="h-8"
        onClick={column.getToggleSortingHandler()}
      >
        <span>{title}</span>
        {renderSortIcon()}
      </Button>
    </div>
  );
};
