import { redirect } from "next/navigation";

/**
 * Landing page for Attack Paths feature
 * Redirects to the integrated attack path analysis view
 */
export default function AttackPathsPage() {
  redirect("/attack-paths/query-builder");
}
