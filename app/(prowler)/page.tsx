import { Spacer } from "@nextui-org/react";

import { StatusChart } from "@/components/charts";
import { FilterControls } from "@/components/filters";
import { Header } from "@/components/ui";
import { CustomBox } from "@/components/ui/custom";

export default function Home() {
  return (
    <>
      <Header title="Scan Overview" icon="solar:pie-chart-2-outline" />
      <Spacer y={4} />
      <FilterControls />
      <Spacer y={10} />
      <div className="grid grid-cols-12 gap-4">
        <CustomBox
          preTitle={"Status"}
          className="col-span-12 md:col-span-8 xl:col-span-5 3xl:col-span-4"
        >
          <StatusChart />
        </CustomBox>
        <CustomBox
          preTitle={"Severity"}
          className="col-span-12 md:col-span-4 xl:col-span-3"
        >
          <p>hi hi</p>
        </CustomBox>
        <CustomBox
          preTitle={"Attack Surface"}
          className="col-span-12 sm:col-span-12 xl:col-span-4 3xl:col-span-5"
        >
          <p>hi hi</p>
        </CustomBox>
      </div>
    </>
  );
}
