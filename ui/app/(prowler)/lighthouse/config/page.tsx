import { redirect } from "next/navigation";

export default function LighthouseConfigRedirectPage() {
  redirect("/lighthouse/settings");
}
