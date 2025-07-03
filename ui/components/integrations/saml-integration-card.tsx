"use client";

import { Card, CardBody, CardHeader } from "@nextui-org/react";
import { Link } from "@nextui-org/react";
import { CheckIcon, Trash2Icon } from "lucide-react";
import { useState } from "react";

import { deleteSamlConfig } from "@/actions/integrations";
import { useToast } from "@/components/ui";
import { CustomAlertModal, CustomButton } from "@/components/ui/custom";

import { SamlConfigForm } from "./forms";

export const SamlIntegrationCard = ({ samlConfig }: { samlConfig?: any }) => {
  const [isSamlModalOpen, setIsSamlModalOpen] = useState(false);
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
      } else if (result.errors?.general) {
        toast({
          variant: "destructive",
          title: "Error removing SAML configuration",
          description: result.errors.general,
        });
      }
    } catch (error) {
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
      <CustomAlertModal
        isOpen={isSamlModalOpen}
        onOpenChange={setIsSamlModalOpen}
        title="Configure SAML SSO"
      >
        <SamlConfigForm
          setIsOpen={setIsSamlModalOpen}
          samlConfig={samlConfig}
        />
      </CustomAlertModal>

      <Card className="dark:bg-prowler-blue-400">
        <CardHeader className="gap-2">
          <div className="flex flex-col gap-1">
            <div className="flex items-center gap-2">
              <h4 className="text-lg font-bold">SAML SSO Integration</h4>
              {id && <CheckIcon className="text-prowler-green" size={20} />}
            </div>
            <p className="text-xs text-gray-500">
              {id ? (
                "SAML Single Sign-On is enabled for this organization"
              ) : (
                <>
                  Configure SAML Single Sign-On for secure authentication.{" "}
                  <Link
                    target="_blank"
                    href="https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/prowler-app-sso"
                    rel="noopener noreferrer"
                    className="text-xs font-medium text-primary"
                  >
                    Read the docs
                  </Link>
                </>
              )}
            </p>
          </div>
        </CardHeader>
        <CardBody>
          <div className="flex items-center justify-between">
            <div className="text-sm">
              <span className="font-medium">Status: </span>
              <span className={id ? "text-prowler-green" : "text-gray-500"}>
                {id ? "Enabled" : "Disabled"}
              </span>
            </div>
            <div className="flex gap-2">
              <CustomButton
                size="sm"
                ariaLabel="Configure SAML SSO"
                color="action"
                onPress={() => setIsSamlModalOpen(true)}
              >
                {id ? "Update" : "Enable"}
              </CustomButton>
              {id && (
                <CustomButton
                  size="sm"
                  ariaLabel="Remove SAML SSO"
                  color="danger"
                  variant="bordered"
                  isLoading={isDeleting}
                  startContent={!isDeleting ? <Trash2Icon size={16} /> : null}
                  onPress={handleRemoveSaml}
                >
                  Remove
                </CustomButton>
              )}
            </div>
          </div>
        </CardBody>
      </Card>
    </>
  );
};
