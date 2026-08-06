import { Card, StatusBadge } from "@rdc/ui";

export function SectionPlaceholder({ description, title, status = "foundation" }: { description: string; title: string; status?: "foundation" | "future" }) {
  return (
    <>
      <div style={{ alignItems: "center", display: "flex", gap: "0.75rem" }}>
        <h1 style={{ margin: 0 }}>{title}</h1>
        <StatusBadge tone={status === "foundation" ? "info" : "neutral"}>{status === "foundation" ? "Foundation shell" : "Future module"}</StatusBadge>
      </div>
      <Card style={{ marginTop: "1.5rem" }}><p style={{ margin: 0 }}>{description}</p></Card>
    </>
  );
}
