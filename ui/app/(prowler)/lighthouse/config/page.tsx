import { redirect } from "next/navigation";

import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

export default function LighthouseConfigRedirectPage() {
  redirect(LIGHTHOUSE_ROUTE.SETTINGS);
}
