"use client";

import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@nextui-org/react";
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
          className="shadow-xl dark:bg-prowler-blue-800"
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
                    className="pointer-events-none flex-shrink-0 text-default-500"
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
