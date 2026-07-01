"use client";

import "@/styles/globals.css";

import { Spacer } from "@heroui/spacer";
import { Icon } from "@iconify/react";
import { useRouter, useSearchParams } from "next/navigation";
import React, { useEffect, useState } from "react";

import {
  getTenantConfig,
  updateTenantConfig,
} from "@/actions/lighthouse/lighthouse";
import { DeleteLLMProviderForm } from "@/components/lighthouse/forms/delete-llm-provider-form";
import { WorkflowConnectLLM } from "@/components/lighthouse/workflow";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { NavigationHeader } from "@/components/ui";
import type { LighthouseProvider } from "@/types/lighthouse";

interface ConnectLLMLayoutProps {
  children: React.ReactNode;
}

export default function ConnectLLMLayout({ children }: ConnectLLMLayoutProps) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const mode = searchParams.get("mode");
  const provider = searchParams.get("provider") as LighthouseProvider | null;
  const isEditMode = mode === "edit";
  const [isDeleteOpen, setIsDeleteOpen] = useState(false);
  const [isDefaultProvider, setIsDefaultProvider] = useState(false);

  // Check if current provider is the default
  useEffect(() => {
    const checkDefaultProvider = async () => {
      if (!provider) return;

      try {
        const config = await getTenantConfig();
        const defaultProvider = config.data?.attributes?.default_provider || "";
        setIsDefaultProvider(provider === defaultProvider);
      } catch (error) {
        console.error("Error checking default provider:", error);
      }
    };

    checkDefaultProvider();
  }, [provider]);

  const handleSetDefault = async () => {
    if (!provider) return;

    await updateTenantConfig({
      default_provider: provider,
    });
    router.push("/lighthouse/config");
  };

  if (!provider) {
    return null;
  }

  return (
    <>
      <Modal
        open={isDeleteOpen}
        onOpenChange={setIsDeleteOpen}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will permanently delete your LLM provider configuration and remove your data from the server."
      >
        <DeleteLLMProviderForm
          providerType={provider}
          setIsOpen={setIsDeleteOpen}
        />
      </Modal>

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
              <div className="flex flex-wrap gap-2">
                {!isDefaultProvider && (
                  <Button
                    aria-label="Set as Default Provider"
                    variant="outline"
                    size="sm"
                    onClick={handleSetDefault}
                    className="w-full sm:w-auto"
                  >
                    <Icon icon="heroicons:star" className="h-4 w-4" />
                    Set as Default
                  </Button>
                )}

                <Button
                  aria-label="Delete Provider"
                  variant="destructive"
                  size="sm"
                  onClick={() => setIsDeleteOpen(true)}
                  className="w-full sm:w-auto"
                >
                  <Icon icon="heroicons:trash" className="h-4 w-4" />
                  Delete Provider
                </Button>
              </div>
              <Spacer y={4} />
            </>
          )}
          {children}
        </div>
      </div>
    </>
  );
}
