"use client";

import { Button, useDisclosure } from "@nextui-org/react";
import React from "react";

import { Header, Modal } from "@/components";

export default function Providers() {
  const { isOpen, onOpen, onClose, onOpenChange } = useDisclosure();

  const onAction = () => {
    onClose();
  };

  return (
    <>
      <Header title="Providers" icon="tabler:zoom-scan" />

      <p>Hi hi from Providers page</p>
      <Button onPress={onOpen}>Open Modal</Button>
      <Modal
        isOpen={isOpen}
        onOpenChange={onOpenChange}
        title="Providers Modal"
        body={
          <>
            <p>Modal body content</p>
          </>
        }
        onAction={onAction}
      />
    </>
  );
}
