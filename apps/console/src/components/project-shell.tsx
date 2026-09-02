"use client";

import { Command, Menu, PanelLeftClose, PanelLeftOpen, Search, X } from "lucide-react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import type { KeyboardEvent, ReactNode } from "react";
import { useEffect, useMemo, useRef, useState } from "react";

import {
  matchProjectNavigationItem,
  projectNavigationSections,
  type ProjectNavigationItem,
} from "@/lib/navigation";

function compactId(value: string) {
  return value.length > 15 ? `${value.slice(0, 7)}…${value.slice(-5)}` : value;
}

function canOpenPaletteFrom(target: EventTarget | null) {
  if (!(target instanceof HTMLElement)) return true;
  return !target.closest("input, textarea, select, [contenteditable='true']");
}

function AvailabilityLabel({
  availability,
}: {
  availability: ProjectNavigationItem["availability"];
}) {
  if (availability === "available") return null;
  return (
    <span className={`nexus-nav-badge nexus-nav-badge--${availability}`}>
      {availability === "foundation" ? "Foundation" : "Planned"}
    </span>
  );
}

export function ProjectShell({
  children,
  orgId,
  projectId,
}: {
  children: ReactNode;
  orgId: string;
  projectId: string;
}) {
  const pathname = usePathname();
  const router = useRouter();
  const root = `/console/organizations/${orgId}/projects/${projectId}`;
  const activeItem = matchProjectNavigationItem(pathname);
  const [collapsed, setCollapsed] = useState(false);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [selectedIndex, setSelectedIndex] = useState(0);
  const drawerCloseRef = useRef<HTMLButtonElement>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const commandEntries = useMemo(
    () =>
      projectNavigationSections.flatMap((section) =>
        section.items.map((item) => ({ item, section: section.label })),
      ),
    [],
  );
  const filteredEntries = useMemo(() => {
    const normalized = query.trim().toLowerCase();
    if (!normalized) return commandEntries;
    return commandEntries.filter(({ item, section }) =>
      [item.label, item.description, section, ...(item.keywords ?? [])]
        .join(" ")
        .toLowerCase()
        .includes(normalized),
    );
  }, [commandEntries, query]);

  useEffect(() => {
    function onGlobalKeyDown(event: globalThis.KeyboardEvent) {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setPaletteOpen((open) => !open);
        return;
      }
      if (
        !event.metaKey &&
        !event.ctrlKey &&
        !event.altKey &&
        canOpenPaletteFrom(event.target) &&
        (event.key === "/" || event.key === "?")
      ) {
        event.preventDefault();
        setPaletteOpen(true);
      }
      if (event.key === "Escape") {
        setDrawerOpen(false);
        setPaletteOpen(false);
      }
    }

    window.addEventListener("keydown", onGlobalKeyDown);
    return () => window.removeEventListener("keydown", onGlobalKeyDown);
  }, []);

  useEffect(() => {
    if (paletteOpen) {
      const returnFocus =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      setQuery("");
      setSelectedIndex(0);
      window.requestAnimationFrame(() => searchRef.current?.focus());
      return () => returnFocus?.focus();
    }
  }, [paletteOpen]);

  useEffect(() => {
    setDrawerOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (drawerOpen) {
      const returnFocus =
        document.activeElement instanceof HTMLElement ? document.activeElement : null;
      window.requestAnimationFrame(() => drawerCloseRef.current?.focus());
      return () => returnFocus?.focus();
    }
  }, [drawerOpen]);

  function navigate(item: ProjectNavigationItem) {
    if (!item.href) return;
    setPaletteOpen(false);
    setDrawerOpen(false);
    router.push(`${root}${item.href}`);
  }

  function onPaletteKeyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "ArrowDown") {
      event.preventDefault();
      setSelectedIndex((index) => Math.min(index + 1, Math.max(filteredEntries.length - 1, 0)));
    } else if (event.key === "ArrowUp") {
      event.preventDefault();
      setSelectedIndex((index) => Math.max(index - 1, 0));
    } else if (event.key === "Enter") {
      event.preventDefault();
      const selection = filteredEntries[selectedIndex];
      if (selection) navigate(selection.item);
    }
  }

  const navigation = (mobile = false) => (
    <nav aria-label={mobile ? "Mobile project navigation" : "Project navigation"}>
      {projectNavigationSections.map((section) => (
        <section className="nexus-nav-section" key={section.label}>
          <h2 className="nexus-nav-section-label">{section.label}</h2>
          <ul className="nexus-nav-list">
            {section.items.map((item) => {
              const Icon = item.icon;
              const isActive = Boolean(item.href && activeItem?.href === item.href);
              const contents = (
                <>
                  <Icon aria-hidden="true" className="nexus-nav-icon" size={17} />
                  <span className="nexus-nav-copy">
                    <span className="nexus-nav-label">{item.label}</span>
                    <AvailabilityLabel availability={item.availability} />
                  </span>
                </>
              );

              return (
                <li key={`${section.label}-${item.label}`}>
                  {item.href ? (
                    <Link
                      aria-current={isActive ? "page" : undefined}
                      aria-label={item.label}
                      className="nexus-nav-item"
                      data-active={isActive || undefined}
                      href={`${root}${item.href}`}
                      title={collapsed && !mobile ? item.label : item.description}
                    >
                      {contents}
                    </Link>
                  ) : (
                    <button
                      aria-disabled="true"
                      aria-label={`${item.label} — planned`}
                      className="nexus-nav-item nexus-nav-item--planned"
                      disabled
                      title={item.description}
                      type="button"
                    >
                      {contents}
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        </section>
      ))}
    </nav>
  );

  return (
    <div className="nexus-shell" data-sidebar-collapsed={collapsed || undefined}>
      <header className="nexus-topbar">
        <button
          aria-expanded={drawerOpen}
          aria-label="Open project navigation"
          className="nexus-icon-button nexus-mobile-menu"
          onClick={() => setDrawerOpen(true)}
          type="button"
        >
          <Menu aria-hidden="true" size={19} />
        </button>
        <Link aria-label="RDC NEXUS dashboard" className="nexus-brand" href={`${root}/dashboard`}>
          <span aria-hidden="true" className="nexus-brand-mark">
            R
          </span>
          <span className="nexus-brand-copy">
            <strong>RDC NEXUS</strong>
            <small>Control plane</small>
          </span>
        </Link>
        <nav aria-label="Breadcrumb" className="nexus-breadcrumbs">
          <span title={orgId}>{compactId(orgId)}</span>
          <span aria-hidden="true">/</span>
          <span title={projectId}>{compactId(projectId)}</span>
          <span aria-hidden="true">/</span>
          <strong>{activeItem?.label ?? "Project"}</strong>
        </nav>
        <div className="nexus-topbar-actions">
          <button
            aria-label="Open command navigation"
            aria-keyshortcuts="Meta+K Control+K"
            className="nexus-command-trigger"
            onClick={() => setPaletteOpen(true)}
            type="button"
          >
            <Search aria-hidden="true" size={16} />
            <span>Navigate</span>
            <kbd>
              <Command aria-hidden="true" size={12} />K
            </kbd>
          </button>
          <Link className="nexus-switch-link" href="/console/select-org">
            Switch organization
          </Link>
        </div>
      </header>

      <div className="nexus-workspace">
        <aside className="nexus-sidebar">
          <button
            aria-label={collapsed ? "Expand navigation" : "Collapse navigation"}
            className="nexus-sidebar-toggle"
            onClick={() => setCollapsed((value) => !value)}
            type="button"
          >
            {collapsed ? (
              <PanelLeftOpen aria-hidden="true" size={17} />
            ) : (
              <PanelLeftClose aria-hidden="true" size={17} />
            )}
            <span>Collapse</span>
          </button>
          <div className="nexus-sidebar-scroll">{navigation()}</div>
          <div className="nexus-sidebar-context">
            <span>Project scope</span>
            <code title={projectId}>{compactId(projectId)}</code>
          </div>
        </aside>

        <main className="nexus-main" id="main-content" tabIndex={-1}>
          {children}
        </main>
      </div>

      {drawerOpen ? (
        <div className="nexus-drawer-layer">
          <button
            aria-label="Close project navigation"
            className="nexus-drawer-scrim"
            onClick={() => setDrawerOpen(false)}
            type="button"
          />
          <aside aria-label="Mobile navigation drawer" className="nexus-drawer">
            <div className="nexus-drawer-header">
              <strong>Project navigation</strong>
              <button
                aria-label="Close project navigation"
                className="nexus-icon-button"
                onClick={() => setDrawerOpen(false)}
                ref={drawerCloseRef}
                type="button"
              >
                <X aria-hidden="true" size={19} />
              </button>
            </div>
            <div className="nexus-drawer-scroll">{navigation(true)}</div>
          </aside>
        </div>
      ) : null}

      {paletteOpen ? (
        <div className="nexus-command-layer">
          <button
            aria-label="Close command navigation"
            className="nexus-command-scrim"
            onClick={() => setPaletteOpen(false)}
            type="button"
          />
          <section
            aria-label="Navigate RDC NEXUS"
            aria-modal="true"
            className="nexus-command-dialog"
            onKeyDown={(event) => {
              if (event.key === "Tab") {
                event.preventDefault();
                searchRef.current?.focus();
              }
            }}
            role="dialog"
          >
            <div className="nexus-command-input-row">
              <Search aria-hidden="true" size={18} />
              <input
                aria-activedescendant={
                  filteredEntries[selectedIndex]
                    ? `nexus-command-option-${selectedIndex}`
                    : undefined
                }
                aria-controls="nexus-command-results"
                aria-expanded="true"
                aria-label="Search project destinations"
                onChange={(event) => {
                  setQuery(event.target.value);
                  setSelectedIndex(0);
                }}
                onKeyDown={onPaletteKeyDown}
                placeholder="Search routes and capabilities…"
                ref={searchRef}
                role="combobox"
                value={query}
              />
              <kbd>Esc</kbd>
            </div>
            <div className="nexus-command-results" id="nexus-command-results" role="listbox">
              {filteredEntries.length ? (
                filteredEntries.map(({ item, section }, index) => {
                  const Icon = item.icon;
                  const selected = index === selectedIndex;
                  return (
                    <button
                      aria-disabled={!item.href}
                      aria-selected={selected}
                      className="nexus-command-result"
                      data-selected={selected || undefined}
                      disabled={!item.href}
                      id={`nexus-command-option-${index}`}
                      key={`${section}-${item.label}`}
                      onClick={() => navigate(item)}
                      role="option"
                      tabIndex={-1}
                      type="button"
                    >
                      <Icon aria-hidden="true" size={17} />
                      <span>
                        <strong>{item.label}</strong>
                        <small>
                          {section} · {item.description}
                        </small>
                      </span>
                      <AvailabilityLabel availability={item.availability} />
                    </button>
                  );
                })
              ) : (
                <p className="nexus-command-empty">No matching capability.</p>
              )}
            </div>
            <footer className="nexus-command-footer">
              <span>
                <kbd>↑</kbd>
                <kbd>↓</kbd> Select
              </span>
              <span>
                <kbd>↵</kbd> Open
              </span>
              <span>Planned capabilities are discoverable, not clickable.</span>
            </footer>
          </section>
        </div>
      ) : null}
    </div>
  );
}
