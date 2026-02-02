"use client";

import { CloudIcon, FolderIcon, ServerIcon } from "lucide-react";
import { useState } from "react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { TreeView } from "@/components/shadcn/tree-view";
import { TreeDataItem } from "@/types/tree";

/**
 * Demo page for the TreeView component.
 *
 * Showcases:
 * 1. TreeView with checkboxes and hierarchical selection
 * 2. TreeView without checkboxes (navigation mode)
 * 3. Custom rendering with renderItem prop
 */

const accountsTreeData: TreeDataItem[] = [
  {
    id: "org-1",
    name: "Organization Root",
    icon: ServerIcon,
    children: [
      {
        id: "ou-1",
        name: "ou-996789098 (Production)",
        icon: FolderIcon,
        children: [
          { id: "acc-1", name: "123456789098", icon: CloudIcon },
          { id: "acc-2", name: "123456789099", icon: CloudIcon },
          { id: "acc-3", name: "123456789100", icon: CloudIcon },
        ],
      },
      {
        id: "ou-2",
        name: "ou-996789099 (Development)",
        icon: FolderIcon,
        children: [
          { id: "acc-4", name: "223456789098", icon: CloudIcon },
          { id: "acc-5", name: "223456789099", icon: CloudIcon },
        ],
      },
      {
        id: "ou-3",
        name: "ou-996789100 (Staging)",
        icon: FolderIcon,
        isLoading: true,
        children: [{ id: "acc-6", name: "323456789098", icon: CloudIcon }],
      },
    ],
  },
];

export default function DemoTreeViewPage() {
  const [selectedIds, setSelectedIds] = useState<string[]>([]);
  const [expandedIds, setExpandedIds] = useState<string[]>(["org-1"]);

  return (
    <div className="container mx-auto space-y-12 p-8">
      <h1 className="text-3xl font-bold">TreeView Component Demo</h1>

      {/* TreeView with Checkboxes */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold">
            TreeView with Checkboxes (Account Selector)
          </h2>
          <p className="text-text-neutral-secondary text-sm">
            Select accounts hierarchically. Selecting a parent selects all
            children.
          </p>
        </div>

        <div className="flex items-start gap-8">
          <div className="bg-bg-neutral-secondary w-96 rounded-lg border p-4">
            <TreeView
              data={accountsTreeData}
              showCheckboxes
              enableSelectChildren
              selectedIds={selectedIds}
              onSelectionChange={setSelectedIds}
              expandedIds={expandedIds}
              onExpandedChange={setExpandedIds}
              renderItem={({ item, isLeaf, hasChildren }) => (
                <div className="flex min-w-0 flex-1 items-center gap-2">
                  {item.icon && <item.icon className="h-4 w-4 shrink-0" />}
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <span className="truncate text-base">{item.name}</span>
                    </TooltipTrigger>
                    <TooltipContent side="top">{item.name}</TooltipContent>
                  </Tooltip>
                  {hasChildren && !isLeaf && (
                    <span className="bg-prowler-white/10 inline-flex min-w-5 shrink-0 items-center justify-center rounded px-1 py-0.5 text-xs tabular-nums">
                      {item.children?.length}
                    </span>
                  )}
                </div>
              )}
            />
          </div>

          <div className="flex-1 space-y-2">
            <h3 className="font-medium">Selected IDs:</h3>
            <pre className="bg-bg-neutral-tertiary overflow-auto rounded p-4 text-sm">
              {JSON.stringify(selectedIds, null, 2)}
            </pre>
          </div>
        </div>
      </section>

      {/* TreeView without Checkboxes */}
      <section className="space-y-4">
        <div>
          <h2 className="text-xl font-semibold">
            TreeView without Checkboxes (Navigation)
          </h2>
          <p className="text-text-neutral-secondary text-sm">
            Click to expand/collapse. Use arrow keys to navigate.
          </p>
        </div>

        <div className="bg-bg-neutral-secondary w-96 rounded-lg border p-4">
          <TreeView
            data={accountsTreeData}
            showCheckboxes={false}
            expandAll={false}
          />
        </div>
      </section>
    </div>
  );
}
