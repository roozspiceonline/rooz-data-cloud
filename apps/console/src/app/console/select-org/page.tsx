import Link from "next/link";
import { Card } from "@rdc/ui";

export default function SelectOrganizationPage() {
  return (
    <main id="main-content" style={{ maxWidth: 960, margin: "0 auto", padding: "4rem 1.5rem" }}>
      <p style={{ color: "var(--muted-foreground)" }}>Rooz Data Cloud</p>
      <h1>Select an organization</h1>
      <p>This foundation shell uses demonstration identifiers until organization APIs are implemented.</p>
      <Card style={{ marginTop: "2rem" }}>
        <h2>Rooz Engineering</h2>
        <p style={{ color: "var(--muted-foreground)" }}>Demo organization and project context.</p>
        <Link href="/console/organizations/org_demo/projects/project_demo/dashboard">Open project dashboard</Link>
      </Card>
    </main>
  );
}
