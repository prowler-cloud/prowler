"use client";

import {
  Dropdown,
  DropdownItem,
  DropdownMenu,
  DropdownSection,
  DropdownTrigger,
} from "@nextui-org/react";
import { Row } from "@tanstack/react-table";
import { CalendarClockIcon, RocketIcon } from "lucide-react";
import { useState } from "react";

import { AddIcon } from "@/components/icons";
import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { ScanOnDemandForm, ScheduleForm } from "../../forms";

interface DataTableRowActionsProps<ProviderProps> {
  row: Row<ProviderProps>;
}
const iconClasses =
  "text-2xl text-default-500 pointer-events-none flex-shrink-0";

export function DataTableRowActions<ProviderProps>({
  row,
}: DataTableRowActionsProps<ProviderProps>) {
  const [isScanOnDemandOpen, setIsScanOnDemandOpen] = useState(false);
  const [isScanScheduleOpen, setIsScanScheduleOpen] = useState(false);

  const providerId = (row.original as { id: string }).id;
  const scanName = (row.original as any).attributes?.name;
  return (
    <>
      <CustomAlertModal
        isOpen={isScanOnDemandOpen}
        onOpenChange={setIsScanOnDemandOpen}
        title="Start Scan On Demand"
        description={"Start a scan on demand for this provider"}
      >
        <ScanOnDemandForm
          providerId={providerId}
          scanName={scanName}
          setIsOpen={setIsScanOnDemandOpen}
        />
      </CustomAlertModal>

      <CustomAlertModal
        isOpen={isScanScheduleOpen}
        onOpenChange={setIsScanScheduleOpen}
        title="Schedule Scan"
        description={"Schedule a scan for this provider"}
      >
        <ScheduleForm
          providerId={providerId}
          scheduleDate={""}
          setIsOpen={setIsScanScheduleOpen}
        />
      </CustomAlertModal>

      <div className="relative flex items-center justify-end gap-2">
        <Dropdown className="shadow-xl" placement="bottom-start">
          <DropdownTrigger>
            <CustomButton
              className="w-full"
              ariaLabel="Start Scan"
              variant="solid"
              color="action"
              size="md"
              endContent={<AddIcon size={20} />}
            >
              Start
            </CustomButton>
          </DropdownTrigger>
          <DropdownMenu
            closeOnSelect
            aria-label="Launch Scan"
            color="default"
            variant="flat"
          >
            <DropdownSection title="Start Scan On Demand">
              <DropdownItem
                key="scanNow"
                color="primary"
                description="Allows you to start a scan on demand"
                textValue="Start now"
                startContent={<RocketIcon className={iconClasses} />}
                onClick={() => setIsScanOnDemandOpen(true)}
              >
                Start now
              </DropdownItem>
            </DropdownSection>
            <DropdownSection title="Schedule Scan">
              <DropdownItem
                key="schedule"
                color="primary"
                description="Schedule a scan for this provider"
                textValue="Schedule Scan"
                startContent={<CalendarClockIcon className={iconClasses} />}
                onClick={() => setIsScanScheduleOpen(true)}
              >
                Schedule Scan
              </DropdownItem>
            </DropdownSection>
          </DropdownMenu>
        </Dropdown>
      </div>
    </>
  );
}
