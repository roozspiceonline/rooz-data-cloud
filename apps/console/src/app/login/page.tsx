import { Card } from "@rdc/ui";

import { LoginForm } from "@/components/login-form";

export default function LoginPage() {
  return (
    <main
      id="main-content"
      style={{
        display: "grid",
        minHeight: "100vh",
        placeItems: "center",
        padding: "1rem",
      }}
    >
      <Card style={{ width: "min(100%, 28rem)" }}>
        <p
          style={{
            color: "var(--muted-foreground)",
            marginTop: 0,
          }}
        >
          Rooz Data Cloud
        </p>
        <h1>Sign in</h1>
        <p>
          Your browser receives an HttpOnly session cookie. RDC does not
          store session credentials in browser storage.
        </p>
        <LoginForm />
      </Card>
    </main>
  );
}
