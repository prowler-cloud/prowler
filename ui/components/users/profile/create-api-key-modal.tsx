"use client";

import { createApiKey } from "@/actions/api-keys/api-keys";
import { Alert, AlertDescription } from "@/components/ui/alert/Alert";
import { CustomAlertModal } from "@/components/ui/custom/custom-alert-modal";

import { DEFAULT_EXPIRY_DAYS } from "./api-keys/constants";
import { ModalButtons } from "./api-keys/modal-buttons";
import { useModalForm } from "./api-keys/use-modal-form";
import { calculateExpiryDate } from "./api-keys/utils";

interface CreateApiKeyModalProps {
  isOpen: boolean;
  onClose: () => void;
  onSuccess: (apiKey: string) => void;
}

interface CreateApiKeyFormData {
  name: string;
  expiresInDays: string;
}

export const CreateApiKeyModal = ({
  isOpen,
  onClose,
  onSuccess,
}: CreateApiKeyModalProps) => {
  const { formData, setFormData, isLoading, error, handleSubmit, handleClose } =
    useModalForm<CreateApiKeyFormData>({
      initialData: {
        name: "",
        expiresInDays: DEFAULT_EXPIRY_DAYS,
      },
      onSubmit: async (data) => {
        if (!data.name.trim()) {
          throw new Error("Name is required");
        }

        const result = await createApiKey({
          name: data.name.trim(),
          expires_at: calculateExpiryDate(parseInt(data.expiresInDays)),
        });

        if (result.error) {
          throw new Error(result.error);
        }

        if (!result.data) {
          throw new Error("Failed to create API key");
        }

        const apiKey = result.data.data.attributes.api_key;
        if (!apiKey) {
          throw new Error("Failed to retrieve API key");
        }

        onSuccess(apiKey);
      },
      onClose,
    });

  return (
    <CustomAlertModal
      isOpen={isOpen}
      onOpenChange={(open) => !open && handleClose()}
      title="Create API Key"
      size="lg"
    >
      <div className="flex flex-col gap-4">
        <div className="flex flex-col gap-2">
          <label
            htmlFor="api-key-name"
            className="text-sm font-medium text-slate-300"
          >
            Name <span className="text-danger">*</span>
          </label>
          <input
            id="api-key-name"
            type="text"
            placeholder="My API Key"
            value={formData.name}
            onChange={(e) =>
              setFormData((prev) => ({ ...prev, name: e.target.value }))
            }
            className="focus:border-prowler-theme-green focus:ring-prowler-theme-green rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:ring-1 focus:outline-none"
            required
          />
          <p className="text-xs text-slate-400">
            A descriptive name to identify this API key
          </p>
        </div>

        <div className="flex flex-col gap-2">
          <label
            htmlFor="api-key-expires"
            className="text-sm font-medium text-slate-300"
          >
            Expires in (days)
          </label>
          <input
            id="api-key-expires"
            type="number"
            value={formData.expiresInDays}
            onChange={(e) =>
              setFormData((prev) => ({
                ...prev,
                expiresInDays: e.target.value,
              }))
            }
            min="1"
            max="3650"
            className="focus:border-prowler-theme-green focus:ring-prowler-theme-green rounded-lg border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-white placeholder-slate-500 focus:ring-1 focus:outline-none"
          />
          <p className="text-xs text-slate-400">
            Number of days until this key expires (default: 1 year)
          </p>
        </div>

        {error && (
          <Alert variant="destructive">
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
      </div>

      <ModalButtons
        onCancel={handleClose}
        onSubmit={handleSubmit}
        isLoading={isLoading}
        isDisabled={!formData.name.trim()}
        submitText="Create API Key"
      />
    </CustomAlertModal>
  );
};
