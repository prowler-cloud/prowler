import { Button } from "@nextui-org/react";
import React from "react";
import { useFormStatus } from "react-dom";

export const ButtonAddProvider = () => {
  const { pending } = useFormStatus();
  return (
    <Button type="submit">{pending ? "Adding..." : "Add provider"}</Button>
  );
};
