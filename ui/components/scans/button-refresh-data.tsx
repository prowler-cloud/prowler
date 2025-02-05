"use client";

import { RefreshCcwIcon } from "lucide-react";
import { useTransition } from "react";

import { CustomButton } from "../ui/custom";

export const ButtonRefreshData = ({
  onPress,
}: {
  onPress: () => Promise<void>;
}) => {
  const [isPending, startTransition] = useTransition();

  return (
    <CustomButton
      ariaLabel="Refresh scan page"
      variant="solid"
      color="action"
      size="md"
      endContent={!isPending && <RefreshCcwIcon size={24} />}
      isLoading={isPending}
      onPress={() => {
        startTransition(async () => {
          await onPress();
        });
      }}
    />
  );
};
