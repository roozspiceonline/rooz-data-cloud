"use client";

import type {
  OrganizationSummary,
  ProjectSummary,
} from "@rdc/shared-types";
import { Card } from "@rdc/ui";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";

import { rdcApi } from "@/lib/rdc-api";

export function OrganizationSelector() {
  const router = useRouter();
  const [organizations, setOrganizations] = useState<
    ReadonlyArray<OrganizationSummary>
  >([]);
  const [loading, setLoading] = useState(true);
  const [openingId, setOpeningId] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  useEffect(() => {
    let active = true;

    async function load() {
      try {
        await rdcApi.session();
        const result = await rdcApi.organizations();
        if (active) setOrganizations(result);
      } catch {
        if (active) router.replace("/login");
      } finally {
        if (active) setLoading(false);
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [router]);

  async function openOrganization(organization: OrganizationSummary) {
    setOpeningId(organization.id);
    setMessage(null);

    try {
      const projects: ReadonlyArray<ProjectSummary> =
        await rdcApi.projects(organization.id);
      const firstProject = projects.at(0);
      if (!firstProject) {
        setMessage(
          `${organization.name} does not have an active project available.`,
        );
        return;
      }
      router.push(
        `/console/organizations/${organization.id}/projects/` +
          `${firstProject.id}/dashboard`,
      );
    } catch {
      setMessage(
        `Unable to access projects for ${organization.name}. Please try again.`,
      );
    } finally {
      setOpeningId(null);
    }
  }

  if (loading) {
    return (
      <div aria-live="polite" role="status" style={{ padding: "1rem 0" }}>
        Loading organizations…
      </div>
    );
  }

  if (organizations.length === 0) {
    return (
      <Card>
        <h2>No organizations available</h2>
        <p>
          Ask an organization owner for access or create an organization
          through the API.
        </p>
      </Card>
    );
  }

  return (
    <div style={{ marginTop: "2rem" }}>
      <ul
        aria-label="Organizations"
        style={{
          display: "grid",
          gap: "1rem",
          listStyle: "none",
          margin: 0,
          padding: 0,
        }}
      >
        {organizations.map((organization) => (
          <li key={organization.id}>
            <Card>
              <h2 style={{ marginTop: 0 }}>{organization.name}</h2>
              <p style={{ color: "var(--muted-foreground)" }}>
                {organization.slug}
              </p>
              <button
                aria-busy={openingId === organization.id}
                disabled={openingId !== null}
                onClick={() => void openOrganization(organization)}
                style={{ minHeight: 44 }}
                type="button"
              >
                {openingId === organization.id
                  ? "Opening…"
                  : "Open organization"}
              </button>
            </Card>
          </li>
        ))}
      </ul>

      {message ? (
        <p
          aria-live="polite"
          role="status"
          style={{ color: "var(--danger)", marginTop: "1rem" }}
        >
          {message}
        </p>
      ) : null}
    </div>
  );
}
