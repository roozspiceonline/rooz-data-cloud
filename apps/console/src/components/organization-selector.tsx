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
        if (active) {
          setOrganizations(result);
        }
      } catch {
        if (active) {
          router.replace("/login");
        }
      } finally {
        if (active) {
          setLoading(false);
        }
      }
    }

    void load();
    return () => {
      active = false;
    };
  }, [router]);

  async function openOrganization(
    organization: OrganizationSummary,
  ) {
    setOpeningId(organization.id);
    setMessage(null);

    try {
      const projects: ReadonlyArray<ProjectSummary> =
        await rdcApi.projects(organization.id);
      const firstProject = projects.at(0);
      if (!firstProject) {
        setMessage(
          `${organization.name} does not have a project yet.`,
        );
        return;
      }
      router.push(
        `/console/organizations/${organization.id}/projects/` +
          `${firstProject.id}/dashboard`,
      );
    } finally {
      setOpeningId(null);
    }
  }

  if (loading) {
    return <p role="status">Loading organizations…</p>;
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
    <div
      style={{
        display: "grid",
        gap: "1rem",
        marginTop: "2rem",
      }}
    >
      {organizations.map((organization) => (
        <Card key={organization.id}>
          <h2 style={{ marginTop: 0 }}>{organization.name}</h2>
          <p style={{ color: "var(--muted-foreground)" }}>
            {organization.slug}
          </p>
          <button
            disabled={openingId === organization.id}
            onClick={() => void openOrganization(organization)}
            style={{ minHeight: 44 }}
            type="button"
          >
            {openingId === organization.id
              ? "Opening…"
              : "Open organization"}
          </button>
        </Card>
      ))}

      {message ? <p role="status">{message}</p> : null}
    </div>
  );
}
