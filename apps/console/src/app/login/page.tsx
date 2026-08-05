import { Card } from "@rdc/ui";

export default function LoginPage() {
  return (
    <main id="main-content" style={{ display: "grid", minHeight: "100vh", placeItems: "center", padding: "1rem" }}>
      <Card style={{ width: "min(100%, 28rem)" }}>
        <p style={{ color: "var(--muted-foreground)", marginTop: 0 }}>Rooz Data Cloud</p>
        <h1>Sign in</h1>
        <p>Phase 1A provides the accessible authentication shell. Session issuance enters the authentication module.</p>
        <button disabled style={{ minHeight: 44, width: "100%" }}>Authentication not enabled yet</button>
      </Card>
    </main>
  );
}
