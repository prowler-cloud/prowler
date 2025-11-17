import { redirect } from "next/navigation";

/**
 * Landing page for Attack Paths feature
 * Redirects to the wizard workflow
 */
export default function AttackPathsPage() {
  redirect("/attack-paths/select-scan");
}
