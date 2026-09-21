import { Link2 } from "lucide-react";

import { ProwlerShort } from "@/components/icons/prowler/ProwlerIcons";

export const AWS_QUICK_WIZARD_STEPS = [
  {
    label: "Connect account",
    description:
      "Enter an IAM role ARN or access keys and test the connection.",
    icon: Link2,
  },
  {
    label: "Name & launch",
    description: "Give the account a name and run the first scan.",
    icon: ProwlerShort,
  },
];
