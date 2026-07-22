"use client";

import { ReactNode } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

import { AdvancedMutelistForm } from "./_components/advanced-mutelist-form";

interface MutelistTabsProps {
  simpleContent: ReactNode;
}

export function MutelistTabs({ simpleContent }: MutelistTabsProps) {
  return (
    <Tabs defaultValue="simple" className="w-full">
      <TabsList className="mb-6">
        <TabsTrigger value="simple">Simple</TabsTrigger>
        <TabsTrigger value="advanced">Advanced</TabsTrigger>
      </TabsList>

      <TabsContent value="simple">{simpleContent}</TabsContent>

      <TabsContent value="advanced">
        <AdvancedMutelistForm />
      </TabsContent>
    </Tabs>
  );
}
