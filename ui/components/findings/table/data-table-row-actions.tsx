"use client";

import { Button } from "@heroui/button";
import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@heroui/dropdown";
import { Row } from "@tanstack/react-table";
import { useState } from "react";

import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { VerticalDotsIcon } from "@/components/icons";
import { JiraIcon } from "@/components/icons/services/IconServices";
import type { FindingProps } from "@/types/components";

interface DataTableRowActionsProps {
  row: Row<FindingProps>;
}

export function DataTableRowActions({ row }: DataTableRowActionsProps) {
  const finding = row.original;
  const [isJiraModalOpen, setIsJiraModalOpen] = useState(false);

  const findingTitle =
    finding.attributes.check_metadata?.checktitle || "Security Finding";

  return (
    <>
      <SendToJiraModal
        isOpen={isJiraModalOpen}
        onOpenChange={setIsJiraModalOpen}
        findingId={finding.id}
        findingTitle={findingTitle}
      />

      <div className="relative flex items-center justify-end gap-2">
        <Dropdown
          className="border-border-neutral-secondary bg-bg-neutral-secondary border shadow-xl"
          placement="bottom"
        >
          <DropdownTrigger>
            <Button isIconOnly radius="full" size="sm" variant="light">
              <VerticalDotsIcon className="text-default-400" />
            </Button>
          </DropdownTrigger>
          <DropdownMenu
            closeOnSelect
            aria-label="Finding actions"
            color="default"
            variant="flat"
          >
            <DropdownSection title="Actions">
              <DropdownItem
                key="jira"
                description="Create a Jira issue for this finding"
                textValue="Send to Jira"
                startContent={
                  <JiraIcon
                    size={20}
                    className="text-default-500 pointer-events-none shrink-0"
                  />
                }
                onPress={() => setIsJiraModalOpen(true)}
              >
                Send to Jira
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
