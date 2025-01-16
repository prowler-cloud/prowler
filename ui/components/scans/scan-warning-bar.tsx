import { Alert, cn } from "@nextui-org/react";

export const ScanWarningBar = () => {
  return (
    <Alert
      color="warning"
      title="Waiting for Your Scan to Show Up?"
      description="Your scan is being processed and may take a few minutes to appear on the table. It will show up shortly."
      variant="faded"
      isClosable
      classNames={{
        base: cn([
          "border-1 border-default-200 dark:border-default-100",
          "gap-x-4",
        ]),
      }}
    />
  );
};
