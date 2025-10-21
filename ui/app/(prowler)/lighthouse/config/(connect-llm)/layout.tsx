"use client";

import "@/styles/globals.css";

import { Spacer } from "@heroui/spacer";
import { Icon } from "@iconify/react";
import { useSearchParams } from "next/navigation";
import React, { useState } from "react";

import { DeleteLLMProviderForm } from "@/components/lighthouse/forms/delete-llm-provider-form";
import { WorkflowConnectLLM } from "@/components/lighthouse/workflow";
import { NavigationHeader } from "@/components/ui";
import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

interface ConnectLLMLayoutProps {
  children: React.ReactNode;
}

export default function ConnectLLMLayout({ children }: ConnectLLMLayoutProps) {
  const searchParams = useSearchParams();
  const mode = searchParams.get("mode");
  const provider = searchParams.get("provider") || "";
  const isEditMode = mode === "edit";
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);

  return (
    <>
      <CustomAlertModal
        isOpen={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your LLM provider configuration and remove your data from the server."
      >
        <DeleteLLMProviderForm
          providerType={provider}
          setIsOpen={setIsDeleteOpen}
        />
      </CustomAlertModal>

      <NavigationHeader
        title={isEditMode ? "Configure LLM Provider" : "Connect LLM Provider"}
        icon="icon-park-outline:close-small"
        href="/lighthouse/config"
      />
      <Spacer y={8} />
      <div className="grid grid-cols-1 gap-8 lg:grid-cols-12">
        <div className="order-1 my-auto hidden h-full lg:col-span-4 lg:col-start-2 lg:block">
          <WorkflowConnectLLM />
        </div>
        <div className="order-2 my-auto lg:col-span-5 lg:col-start-6">
          {isEditMode && provider && (
            <>
              <CustomButton
                ariaLabel="Delete Provider"
                variant="bordered"
                color="danger"
                size="sm"
                startContent={
                  <Icon icon="heroicons:trash" className="h-4 w-4" />
                }
                onPress={() => setIsDeleteOpen(true)}
              >
                Delete Provider
              </CustomButton>
              <Spacer y={4} />
            </>
          )}
          {children}
        </div>
      </div>
    </>
  );
}
