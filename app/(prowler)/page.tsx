import { Spacer } from "@nextui-org/react";

import { SeverityChart, StatusChart } from "@/components/charts";
import { AttackSurface } from "@/components/overview";
import { Header } from "@/components/ui";
import { CustomBox } from "@/components/ui/custom";

export default function Home() {
  return (
    <>
      <Header title="Scan Overview" icon="solar:pie-chart-2-outline" />
      <Spacer y={4} />
      <Spacer y={10} />
      <div className="grid grid-cols-12 gap-4">
        <CustomBox
          preTitle={"Findings by Status"}
          className="col-span-12 md:col-span-8 xl:col-span-5"
        >
          <StatusChart />
        </CustomBox>
        <CustomBox
          preTitle={"Findings by Severity"}
          className="col-span-12 md:col-span-4 xl:col-span-3"
        >
          <SeverityChart />
        </CustomBox>
        <CustomBox
          preTitle={"Attack Surface"}
          className="col-span-12 sm:col-span-12 xl:col-span-4"
        >
          <AttackSurface />
        </CustomBox>
      </div>
    </>
  );
}
