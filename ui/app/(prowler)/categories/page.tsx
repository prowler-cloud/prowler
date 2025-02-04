import { Spacer } from "@nextui-org/react";

import { Header } from "@/components/ui";

export default async function Categories() {
  return (
    <>
      <Header title="Categories" icon="material-symbols:folder-open-outline" />
      <Spacer y={4} />
    </>
  );
}
