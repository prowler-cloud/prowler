"use client";

import { Cell, flexRender, Row } from "@tanstack/react-table";
import { motion } from "framer-motion";

import { cn } from "@/lib/utils";

interface DataTableAnimatedRowProps<TData> {
  row: Row<TData>;
}

/**
 * DataTableAnimatedRow renders a table row with smooth expand/collapse animations.
 *
 * The trick: You cannot animate <tr> height directly (tables ignore it).
 * Instead, we wrap each cell's content in a motion.div and animate THAT.
 *
 * How it works:
 * 1. The <tr> itself is not animated
 * 2. Each <td> contains a motion.div wrapper
 * 3. The wrapper animates height from 0 to "auto"
 * 4. overflow-hidden clips content during animation
 * 5. Padding is on the inner content, not the td
 */
export function DataTableAnimatedRow<TData>({
  row,
}: DataTableAnimatedRowProps<TData>) {
  return (
    <motion.tr
      initial="collapsed"
      animate="open"
      exit="collapsed"
      variants={{
        open: { opacity: 1 },
        collapsed: { opacity: 0 },
      }}
      transition={{ duration: 0.2 }}
      data-state={row.getIsSelected() ? "selected" : undefined}
      className={cn(
        "transition-colors",
        "[&>td:first-child]:rounded-l-full [&>td:last-child]:rounded-r-full",
        "hover:bg-bg-neutral-tertiary",
        "data-[state=selected]:bg-bg-neutral-tertiary",
      )}
    >
      {row.getVisibleCells().map((cell: Cell<TData, unknown>, index, cells) => {
        const isFirst = index === 0;
        const isLast = index === cells.length - 1;

        return (
          <td key={cell.id} className="overflow-hidden p-0">
            <motion.div
              initial="collapsed"
              animate="open"
              exit="collapsed"
              variants={{
                open: {
                  height: "auto",
                  opacity: 1,
                  transition: {
                    height: { duration: 0.2, ease: "easeOut" },
                    opacity: { duration: 0.15, delay: 0.05 },
                  },
                },
                collapsed: {
                  height: 0,
                  opacity: 0,
                  transition: {
                    height: { duration: 0.2, ease: "easeIn" },
                    opacity: { duration: 0.1 },
                  },
                },
              }}
              className="overflow-hidden"
            >
              <div
                className={cn(
                  "px-1.5 py-2",
                  isFirst && "pl-3",
                  isLast && "pr-3",
                )}
              >
                {flexRender(cell.column.columnDef.cell, cell.getContext())}
              </div>
            </motion.div>
          </td>
        );
      })}
    </motion.tr>
  );
}
