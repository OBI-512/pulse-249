import type { ReactNode } from "react";
import type { AuthUser, Health, Page } from "../types";
import type { ViewDefinition } from "../config/views";
import { API } from "../api/client";
import { AppFooter, AppHeader, type ThemeMode } from "../components/common/AppChrome";
import { HoverHelpOverlay } from "../components/common/HoverHelpOverlay";

type AppShellProps = {
  user: AuthUser;
  health: Health | null;
  nav: ViewDefinition[];
  page: Page;
  busy: boolean;
  theme: ThemeMode;
  onTheme: (theme: ThemeMode) => void;
  onPage: (page: Page) => void;
  onRefresh: () => void;
  onLogout: () => void;
  children: ReactNode;
};

export function AppShell({
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
  children,
}: AppShellProps) {
  return (
    <div className="app-shell">
      <HoverHelpOverlay />
      <AppHeader
        user={user}
        health={health}
        nav={nav}
        page={page}
        busy={busy}
        theme={theme}
        onTheme={onTheme}
        onPage={onPage}
        onRefresh={onRefresh}
        onLogout={onLogout}
      />

      <main className="content">{children}</main>

      <AppFooter health={health} user={user} endpoint={API} />
    </div>
  );
}
