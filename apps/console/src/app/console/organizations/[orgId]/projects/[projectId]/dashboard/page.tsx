import { Card, StatusBadge } from "@rdc/ui";

const foundations = [["Console", "ready"], ["API shell", "ready"], ["PostgreSQL", "configured"], ["Redis", "configured"], ["Object storage", "configured"]] as const;

export default function DashboardPage() {
  return (
    <>
      <p style={{ color: "var(--muted-foreground)", marginBottom: "0.35rem" }}>Engineering foundation</p>
      <h1 style={{ marginTop: 0 }}>Project dashboard</h1>
      <p>Phase 1A proves repository, development topology, health boundaries, and accessible console structure before domain implementation.</p>
      <div style={{ display: "grid", gap: "1rem", gridTemplateColumns: "repeat(auto-fit, minmax(12rem, 1fr))", marginTop: "2rem" }}>
        {foundations.map(([name, status]) => <Card key={name}><p style={{ color: "var(--muted-foreground)", marginTop: 0 }}>{name}</p><StatusBadge tone="success">{status}</StatusBadge></Card>)}
      </div>
    </>
  );
}
