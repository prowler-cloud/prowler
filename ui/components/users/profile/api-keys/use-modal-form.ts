import { useState } from "react";

interface UseModalFormOptions<TFormData> {
  initialData: TFormData;
  onSubmit: (data: TFormData) => Promise<void>;
  onSuccess?: () => void;
  onClose: () => void;
}

interface UseModalFormReturn<TFormData> {
  formData: TFormData;
  setFormData: React.Dispatch<React.SetStateAction<TFormData>>;
  isLoading: boolean;
  error: string | null;
  setError: (error: string | null) => void;
  handleSubmit: () => Promise<void>;
  handleClose: () => void;
  resetForm: () => void;
}

/**
 * Custom hook to manage modal form state and submission logic
 * Reduces boilerplate in modal components
 */
export const useModalForm = <TFormData>({
  initialData,
  onSubmit,
  onSuccess,
  onClose,
}: UseModalFormOptions<TFormData>): UseModalFormReturn<TFormData> => {
  const [formData, setFormData] = useState<TFormData>(initialData);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const resetForm = () => {
    setFormData(initialData);
    setError(null);
  };

  const handleSubmit = async () => {
    setIsLoading(true);
    setError(null);

    try {
      await onSubmit(formData);
      resetForm();
      onSuccess?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred");
    } finally {
      setIsLoading(false);
    }
  };

  const handleClose = () => {
    resetForm();
    onClose();
  };

  return {
    formData,
    setFormData,
    isLoading,
    error,
    setError,
    handleSubmit,
    handleClose,
    resetForm,
  };
};
