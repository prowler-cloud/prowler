"use client";

import { CheckIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { deleteSamlConfig } from "@/actions/integrations";
import { Button } from "@/components/shadcn";
import { Modal } from "@/components/shadcn/modal";
import { useToast } from "@/components/ui";
import { CustomLink } from "@/components/ui/custom/custom-link";

import { Card, CardContent, CardHeader } from "../../shadcn";
import { SamlConfigForm } from "./saml-config-form";

export const SamlIntegrationCard = ({ samlConfig }: { samlConfig?: any }) => {
  const [isSamlModalOpen, setIsSamlModalOpen] = useState(false);
  const [isDeleteModalOpen, setIsDeleteModalOpen] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const { toast } = useToast();
  const id = samlConfig?.id;

  const handleRemoveSaml = async () => {
    if (!id) return;

    setIsDeleting(true);
    try {
      const result = await deleteSamlConfig(id);

      if (result.success) {
        toast({
          title: "SAML configuration removed",
          description: result.success,
        });
        setIsDeleteModalOpen(false);
      } else if (result.errors?.general) {
        toast({
          variant: "destructive",
          title: "Error removing SAML configuration",
          description: result.errors.general,
        });
      }
    } catch {
      toast({
        variant: "destructive",
        title: "Error",
        description: "Failed to remove SAML configuration. Please try again.",
      });
    } finally {
      setIsDeleting(false);
    }
  };

  return (
    <>
      {/* Configure SAML Modal */}
      <Modal
        open={isSamlModalOpen}
        onOpenChange={setIsSamlModalOpen}
        title="Configure SAML SSO"
      >
        <SamlConfigForm
          setIsOpen={setIsSamlModalOpen}
          samlConfig={samlConfig}
        />
      </Modal>

      {/* Delete Confirmation Modal */}
      <Modal
        open={isDeleteModalOpen}
        onOpenChange={setIsDeleteModalOpen}
        title="Remove SAML Configuration"
        size="md"
      >
        <div className="flex flex-col gap-4">
          <p className="text-default-600 text-sm">
            Are you sure you want to remove the SAML SSO configuration? Users
            will no longer be able to sign in using SAML.
          </p>
          <div className="flex w-full justify-end gap-4">
            <Button
              type="button"
              variant="ghost"
              size="lg"
              onClick={() => setIsDeleteModalOpen(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              type="button"
              variant="destructive"
              size="lg"
              disabled={isDeleting}
              onClick={handleRemoveSaml}
            >
              <Trash2Icon className="size-4" />
              {isDeleting ? "Removing..." : "Remove"}
            </Button>
          </div>
        </div>
      </Modal>

      <Card variant="base" padding="lg">
        <CardHeader>
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <h4 className="text-lg font-bold">SAML SSO Integration</h4>
              {id && <CheckIcon className="text-button-primary" size={20} />}
            </div>
            <p className="text-xs text-gray-500">
              {id ? (
                "SAML Single Sign-On is enabled for this organization"
              ) : (
                <>
                  Configure SAML Single Sign-On for secure authentication.{" "}
                  <CustomLink href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-sso">
                    Read the docs
                  </CustomLink>
                </>
              )}
            </p>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <span className="font-medium">Status: </span>
              <span className={id ? "text-button-primary" : "text-gray-500"}>
                {id ? "Enabled" : "Disabled"}
              </span>
            </div>
            <div className="flex gap-2">
              <Button size="sm" onClick={() => setIsSamlModalOpen(true)}>
                {id ? "Update" : "Enable"}
              </Button>
              {id && (
                <Button
                  size="sm"
                  variant="destructive"
                  onClick={() => setIsDeleteModalOpen(true)}
                >
                  <Trash2Icon size={16} />
                  Remove
                </Button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>
    </>
  );
};
