import { useEffect, useMemo, useState, type ReactNode } from "react";
import type { AuthUser, Health, Page } from "../../types";
import { viewDefinition } from "../../config/views";
import { Button } from "../../design-system/primitives";

type NavItem = { id: Page; label: string; description: string };
export type ThemeMode = "light" | "operations" | "night";

function Icon({ name }: { name: string }) {
  const paths: Record<string, ReactNode> = {
    menu: <><path d="M4 7h16M4 12h16M4 17h16" /></>,
    refresh: <><path d="M20 11a8 8 0 1 0-2.34 5.66"/><path d="M20 4v7h-7"/></>,
    palette: <><path d="M12 3a9 9 0 1 0 0 18h1.3a1.8 1.8 0 0 0 1.7-2.4 1.8 1.8 0 0 1 1.7-2.4H18a3 3 0 0 0 3-3A10 10 0 0 0 12 3Z"/><circle cx="7.5" cy="10" r="1"/><circle cx="10" cy="6.8" r="1"/><circle cx="14.2" cy="6.8" r="1"/><circle cx="16.7" cy="10" r="1"/></>,
    sun: <><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></>,
    operations: <><circle cx="12" cy="12" r="8"/><path d="M12 4v16M4 12h16"/><path d="M6.3 6.3 17.7 17.7M17.7 6.3 6.3 17.7" opacity=".45"/></>,
    moon: <><path d="M20 15.5A8.5 8.5 0 0 1 8.5 4 8.5 8.5 0 1 0 20 15.5Z"/></>,
    user: <><circle cx="12" cy="8" r="3.5"/><path d="M5 20c.8-4 3.2-6 7-6s6.2 2 7 6"/></>,
    chevron: <><path d="m7 10 5 5 5-5"/></>,
    overview: <><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></>,
    alarms: <><path d="M12 3a6 6 0 0 0-6 6v4l-2 3h16l-2-3V9a6 6 0 0 0-6-6Z"/><path d="M9.5 19a2.7 2.7 0 0 0 5 0"/></>,
    maintenance: <><path d="M4 7h16M7 4v6M17 4v6M5 10h14v10H5z"/><path d="m9 15 2 2 4-4"/></>,
    discovery: <><circle cx="11" cy="11" r="6"/><path d="m16 16 4 4M11 7v8M7 11h8"/></>,
    devices: <><rect x="4" y="5" width="16" height="10" rx="2"/><path d="M8 19h8M12 15v4"/></>,
    network: <><circle cx="12" cy="5" r="2.5"/><circle cx="5" cy="18" r="2.5"/><circle cx="19" cy="18" r="2.5"/><path d="M10.8 7.2 6.2 15.8M13.2 7.2l4.6 8.6M7.5 18h9"/></>,
    groups: <><circle cx="8" cy="9" r="3"/><circle cx="16.5" cy="10" r="2.5"/><path d="M3 20c.6-4 2.4-6 5-6 2.7 0 4.5 2 5 6M13 20c.4-3 1.8-4.7 4-4.7 2.1 0 3.5 1.6 4 4.7"/></>,
    customers: <><circle cx="9" cy="8" r="3"/><path d="M4 20c.5-4 2.2-6 5-6s4.5 2 5 6"/><path d="M17 7v6M14 10h6"/></>,
    topology: <><circle cx="12" cy="5" r="2.4"/><circle cx="6" cy="18" r="2.4"/><circle cx="18" cy="18" r="2.4"/><path d="M12 7.4v4.2M12 11.6 6.8 15.8M12 11.6l5.2 4.2"/></>,
    "data-reporting": <><path d="M4 19V9M10 19V5M16 19v-7M22 19H2"/><path d="m4 7 6-4 6 6 5-4"/></>,
    recycle: <><path d="M7 7h10l-.8 13H7.8L7 7ZM5 7h14M9 7V4h6v3"/></>,
    restore: <><path d="M5 8a8 8 0 1 1-1 8"/><path d="M5 3v5h5"/><path d="M12 8v5l3 2"/></>,
    logs: <><path d="M6 4h12v16H6zM9 8h6M9 12h6M9 16h4"/></>,
    users: <><circle cx="9" cy="8" r="3"/><circle cx="17" cy="9" r="2.5"/><path d="M3 20c.6-4 2.6-6 6-6s5.4 2 6 6M14 20c.4-2.6 1.8-4 4-4 1.6 0 2.8.7 3.5 2"/></>,
    settings: <><circle cx="12" cy="12" r="3"/><path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M18.4 5.6l-2.1 2.1M7.7 16.3l-2.1 2.1"/></>,
    account: <><circle cx="12" cy="8" r="3.5"/><path d="M5 20c.8-4 3.2-6 7-6s6.2 2 7 6"/></>,
    signout: <><path d="M10 5H5v14h5M14 8l4 4-4 4M9 12h9"/></>,
    candidates: <><path d="M5 4h14v16H5zM8 8h8M8 12h5M8 16h7"/></>,
  };
  return <svg viewBox="0 0 24 24" aria-hidden="true" className="shell-icon" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">{paths[name] || paths.overview}</svg>;
}


export function AppHeader({
  user,
  health,
  nav,
  page,
  busy,
  theme,
  onTheme,
  onPage,
  onRefresh,
  onLogout,
}: {
  user: AuthUser;
  health: Health | null;
  nav: NavItem[];
  page: Page;
  busy: boolean;
  theme: ThemeMode;
  onTheme: (theme: ThemeMode) => void;
  onPage: (page: Page) => void;
  onRefresh: () => void;
  onLogout: () => void;
}) {
  const [navOpen, setNavOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [appearanceOpen, setAppearanceOpen] = useState(false);
  const currentView = viewDefinition(page);
  const initials = useMemo(() => {
    const source = (user.display_name || user.username).trim();
    const parts = source.split(/\s+/).filter(Boolean);
    return (parts.length > 1 ? `${parts[0][0]}${parts[parts.length - 1][0]}` : source.slice(0, 2)).toUpperCase();
  }, [user.display_name, user.username]);

  const adminPages = new Set<Page>(["recycle", "restore-points", "logs", "users", "settings"]);
  const operations = nav.filter((item) => item.id !== "account" && !adminPages.has(item.id));
  const administration = nav.filter((item) => adminPages.has(item.id));
  const themes: Array<{ id: ThemeMode; label: string; description: string; icon: string }> = [
    { id: "light", label: "Light", description: "Bright high-contrast workspace", icon: "sun" },
    { id: "operations", label: "Operations", description: "Balanced FTTW operations theme", icon: "operations" },
    { id: "night", label: "Night", description: "Low-glare dark operations view", icon: "moon" },
  ];
  const activeTheme = themes.find((item) => item.id === theme) || themes[1];

  useEffect(() => {
    if (!navOpen && !accountOpen && !appearanceOpen) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setNavOpen(false);
        setAccountOpen(false);
        setAppearanceOpen(false);
      }
    };
    const onPointer = (event: PointerEvent) => {
      const target = event.target as HTMLElement | null;
      if (accountOpen && !target?.closest(".header-account-wrap")) setAccountOpen(false);
      if (appearanceOpen && !target?.closest(".header-theme-wrap")) setAppearanceOpen(false);
      if (navOpen && !target?.closest(".app-menu-drawer") && !target?.closest(".header-menu-button")) setNavOpen(false);
    };
    document.addEventListener("keydown", onKey);
    document.addEventListener("pointerdown", onPointer);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.removeEventListener("pointerdown", onPointer);
    };
  }, [navOpen, accountOpen, appearanceOpen]);

  const openPage = (target: Page) => {
    setNavOpen(false);
    setAccountOpen(false);
    setAppearanceOpen(false);
    onPage(target);
  };

  return (
    <>
      <header className="app-header">
        <div className="app-header-left">
          <Button unstyled
            className={navOpen ? "header-menu-button active" : "header-menu-button"}
            type="button"
            onClick={() => { setNavOpen((value) => !value); setAccountOpen(false); setAppearanceOpen(false); }}
            aria-expanded={navOpen}
            aria-label="Open application navigation"
            title="Application navigation"
          >
            <Icon name="menu" />
          </Button>
          <div className="brand-block" onClick={() => openPage("overview")} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") openPage("overview"); }} role="button" tabIndex={0}>
            <img className="brand-logo" src="/branding/logo.png" alt="" aria-hidden="true" />
            <div>
              <div className="brand-kicker">FTTW NETWORK OPERATIONS</div>
              <strong>Network Management System</strong>
            </div>
          </div>
        </div>

        <div className="header-current-view" aria-label={`Current view: ${currentView.label}`}>
          <span className="header-current-view-icon"><Icon name={currentView.icon} /></span>
          <strong>{currentView.label}</strong>
        </div>

        <div className="header-actions">
          <div className={`header-health ${health?.status === "online" ? "online" : "offline"}`}>
            <span className="live-pulse" />
            <div><small>Platform</small><strong>{health?.status === "online" ? "Online" : "Checking"}</strong></div>
          </div>
          <div className="header-theme-wrap">
            <Button unstyled
              className={appearanceOpen ? "header-icon-button header-theme-button active" : "header-icon-button header-theme-button"}
              type="button"
              onClick={() => { setAppearanceOpen((value) => !value); setAccountOpen(false); setNavOpen(false); }}
              title={`Appearance: ${activeTheme.label}`}
              aria-label="Choose application theme"
              aria-expanded={appearanceOpen}
            >
              <Icon name="palette" />
            </Button>
            {appearanceOpen && <div className="header-theme-menu" role="menu" aria-label="Application appearance">
              <div className="theme-menu-title"><span>Appearance</span><small>Choose your workspace theme</small></div>
              {themes.map((item) => (
                <Button unstyled key={item.id} type="button" role="menuitemradio" aria-checked={theme === item.id} className={theme === item.id ? "theme-option active" : "theme-option"} onClick={() => { onTheme(item.id); setAppearanceOpen(false); }}>
                  <span className="theme-option-icon"><Icon name={item.icon} /></span>
                  <span><strong>{item.label}</strong><small>{item.description}</small></span>
                  <i aria-hidden="true" />
                </Button>
              ))}
            </div>}
          </div>
          <Button unstyled className="header-icon-button" type="button" onClick={onRefresh} disabled={busy} title="Refresh current view" aria-label="Refresh current view">
            <Icon name="refresh" />
          </Button>
          <div className="header-account-wrap">
            <Button unstyled
              className={accountOpen ? "header-account-button active" : "header-account-button"}
              type="button"
              onClick={() => { setAccountOpen((value) => !value); setNavOpen(false); setAppearanceOpen(false); }}
              aria-expanded={accountOpen}
              aria-label="Open user account menu"
            >
              <span className="header-user-avatar">{initials}</span>
              <span className="header-user-copy"><strong>{user.display_name || user.username}</strong><small>{user.roles[0] || "No role"}</small></span>
              <span className="header-account-chevron"><Icon name="chevron" /></span>
            </Button>
            {accountOpen && <div className="header-account-menu" role="menu">
              <div className="account-menu-identity">
                <span>Signed in as</span>
                <strong>{user.display_name || user.username}</strong>
                <small>@{user.username}</small>
              </div>
              <Button unstyled type="button" role="menuitem" onClick={() => openPage("account")}><Icon name="account" /><span><strong>My Account</strong><small>Profile and account management</small></span></Button>
              <div className="account-menu-divider" />
              <Button unstyled type="button" role="menuitem" className="account-menu-signout" onClick={() => { setAccountOpen(false); onLogout(); }}><Icon name="signout" /><span><strong>Sign out</strong><small>End this management session</small></span></Button>
            </div>}
          </div>
        </div>
      </header>

      <nav className="workspace-nav-strip" aria-label="Primary operational view navigation">
        <div className="workspace-nav-scroll">
          {operations.map((item) => (
            <Button unstyled
              key={item.id}
              type="button"
              className={page === item.id ? "workspace-nav-item active" : "workspace-nav-item"}
              onClick={() => openPage(item.id)}
              aria-current={page === item.id ? "page" : undefined}
              title={item.description}
            >
              <span className="workspace-nav-icon"><Icon name={viewDefinition(item.id).icon} /></span>
              <span>{item.label}</span>
            </Button>
          ))}
        </div>
      </nav>

      {navOpen && <Button unstyled className="app-menu-backdrop" type="button" aria-label="Close application navigation" onClick={() => setNavOpen(false)} />}
      <aside className={navOpen ? "app-menu-drawer open" : "app-menu-drawer"} aria-hidden={!navOpen}>
        <div className="drawer-heading">
          <div className="drawer-heading-copy">
            <span>Application navigation</span>
            <strong>Operations Console</strong>
            <small>{currentView.label} · {nav.length} available views</small>
          </div>
          <div className="drawer-heading-theme">
            <div className="drawer-heading-theme-label"><span>Appearance</span><small>{activeTheme.label}</small></div>
            <div className="drawer-theme-selector drawer-theme-selector-top" role="radiogroup" aria-label="Application theme">
              {themes.map((item) => (
                <Button unstyled key={item.id} type="button" role="radio" aria-checked={theme === item.id} className={theme === item.id ? "drawer-theme-option active" : "drawer-theme-option"} onClick={() => onTheme(item.id)} title={item.description}>
                  <Icon name={item.icon} /><span>{item.label}</span>
                </Button>
              ))}
            </div>
          </div>
        </div>

        <div className="drawer-scroll-area">
          <div className="drawer-section">
            <div className="drawer-section-title"><span>Operations</span><small>{operations.length} views</small></div>
            <div className="drawer-nav-list">
              {operations.map((item) => <Button unstyled key={item.id} type="button" className={page === item.id ? "drawer-nav-item active" : "drawer-nav-item"} onClick={() => openPage(item.id)}><span className="drawer-nav-icon"><Icon name={viewDefinition(item.id).icon} /></span><span><strong>{item.label}</strong><small>{item.description}</small></span></Button>)}
            </div>
          </div>

          {administration.length > 0 && <div className="drawer-section">
            <div className="drawer-section-title"><span>Administration</span><small>{administration.length} views</small></div>
            <div className="drawer-nav-list">
              {administration.map((item) => <Button unstyled key={item.id} type="button" className={page === item.id ? "drawer-nav-item active" : "drawer-nav-item"} onClick={() => openPage(item.id)}><span className="drawer-nav-icon"><Icon name={viewDefinition(item.id).icon} /></span><span><strong>{item.label}</strong><small>{item.description}</small></span></Button>)}
            </div>
          </div>}

        </div>

        <div className="drawer-system-foot">
          <span className={health?.status === "online" ? "online" : "offline"}><i />Platform {health?.status || "unknown"}</span>
          <span>{user.username}</span>
        </div>
      </aside>
    </>
  );
}

export function AppFooter({ user }: { health: Health | null; user: AuthUser; endpoint: string }) {
  const year = new Date().getFullYear();
  return (
    <footer className="app-footer">
      <div className="footer-product">
        <img className="footer-brand-logo" src="/branding/logo.png" alt="" aria-hidden="true" />
        <div><strong>FTTW Network Management System</strong><span>Operations & engineering console</span></div>
      </div>
      <div className="footer-meta">
        <span>{user.display_name || user.username}</span>
        <span className="footer-divider">•</span>
        <span>© {year} FTTW NMS</span>
      </div>
    </footer>
  );
}



