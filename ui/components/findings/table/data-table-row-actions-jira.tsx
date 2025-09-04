"use client";

import {
  Button,
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@nextui-org/react";
import { Send } from "lucide-react";
import { useState } from "react";

import { VerticalDotsIcon } from "@/components/icons";
import { JiraIcon } from "@/components/icons/services/IconServices";
import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { FindingProps } from "@/types";

interface DataTableRowActionsJiraProps {
  finding: FindingProps;
}

export function DataTableRowActionsJira({
  finding,
}: DataTableRowActionsJiraProps) {
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
        <Dropdown className="shadow-xl dark:bg-prowler-blue-800" placement="bottom">
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
                    className="text-default-500 pointer-events-none flex-shrink-0"
                  />
                }
                onPress={() => setIsJiraModalOpen(true)}
              >
                Send to Jira
              </DropdownItem>
              
              {/* Placeholder for future integrations */}
              <DropdownItem
                key="slack"
                description="Send notification to Slack (Coming soon)"
                textValue="Send to Slack"
                startContent={
                  <Send
                    size={20}
                    className="text-default-500 pointer-events-none flex-shrink-0"
                  />
                }
                isDisabled
                className="opacity-50"
              >
                Send to Slack
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}