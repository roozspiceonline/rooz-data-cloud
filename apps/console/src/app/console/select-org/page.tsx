import { OrganizationSelector } from "@/components/organization-selector";

export default function SelectOrganizationPage() {
  return (
    <main
      id="main-content"
      style={{
        margin: "0 auto",
        maxWidth: 960,
        padding: "4rem 1.5rem",
      }}
    >
      <p style={{ color: "var(--muted-foreground)" }}>
        Rooz Data Cloud
      </p>
      <h1>Select an organization</h1>
      <p>
        Only organizations allowed by your server-side memberships
        appear here.
      </p>
      <OrganizationSelector />
    </main>
  );
}
