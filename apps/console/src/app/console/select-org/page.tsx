import { OrganizationSelector } from "@/components/organization-selector";

export default function SelectOrganizationPage() {
  return (
    <main className="selection-layout" id="main-content">
      <p className="auth-eyebrow">RDC NEXUS</p>
      <h1>Select an organization</h1>
      <p>Only organizations allowed by your server-side memberships appear here.</p>
      <OrganizationSelector />
    </main>
  );
}
