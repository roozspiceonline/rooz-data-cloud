import { Card } from "@rdc/ui";
import { LockKeyhole } from "lucide-react";

import { LoginForm } from "@/components/login-form";

export default function LoginPage() {
  return (
    <main className="auth-layout" id="main-content">
      <div className="auth-frame">
        <header>
          <p className="auth-eyebrow">RDC NEXUS</p>
          <h1 className="auth-title">Operate the cloud with evidence.</h1>
          <p className="auth-subtitle">
            Build, execute, and inspect secure Agents from one tenant-scoped control plane.
          </p>
        </header>
        <Card style={{ width: "100%" }}>
          <div className="auth-card">
            <p className="auth-eyebrow">Secure console</p>
            <h2>Sign in</h2>
            <p className="auth-card-copy">
              Use the RDC account granted access to your organization.
            </p>
            <LoginForm />
            <p className="auth-security-note">
              <LockKeyhole aria-hidden="true" size={15} />
              <span>
                Your browser receives an HttpOnly session cookie. RDC does not store session
                credentials in browser storage.
              </span>
            </p>
          </div>
        </Card>
      </div>
    </main>
  );
}
