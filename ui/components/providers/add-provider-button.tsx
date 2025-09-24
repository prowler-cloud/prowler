"use client";

import { ChevronDownIcon, FileTextIcon, PlusIcon } from "lucide-react";
import { useState } from "react";

import { AddIcon } from "../icons";
import { CustomButton } from "../ui/custom";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "../ui/dropdown-menu";
import { BulkImportModal } from "./bulk-import";

export const AddProviderButton = () => {
  const [isBulkImportOpen, setIsBulkImportOpen] = useState(false);

  return (
    <>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <CustomButton
            ariaLabel="Add Cloud Provider"
            variant="solid"
            color="action"
            size="md"
            endContent={
              <div className="flex items-center gap-1">
                <AddIcon size={20} />
                <ChevronDownIcon size={16} />
              </div>
            }
          >
            Add Cloud Provider
          </CustomButton>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-56">
          <DropdownMenuItem asChild>
            <a
              href="/providers/connect-account"
              className="flex items-center gap-2 cursor-pointer"
            >
              <PlusIcon size={16} />
              Add Single Provider
            </a>
          </DropdownMenuItem>
          <DropdownMenuSeparator />
          <DropdownMenuItem 
            onClick={() => setIsBulkImportOpen(true)}
            className="flex items-center gap-2 cursor-pointer"
          >
            <FileTextIcon size={16} />
            Bulk Import from YAML
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>

      <BulkImportModal
        isOpen={isBulkImportOpen}
        onClose={() => setIsBulkImportOpen(false)}
        onSuccess={() => {
          // Refresh the page to show new providers
          window.location.reload();
        }}
      />
    </>
  );
};
