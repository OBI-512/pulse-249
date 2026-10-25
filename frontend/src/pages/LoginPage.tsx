import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import "../login-sophisticated.css";
import { Button, Checkbox, Input } from "../design-system/primitives";

type LoginPageProps = {
  username: string;
  password: string;
  rememberMe: boolean;
  setUsername: (value: string) => void;
  setPassword: (value: string) => void;
  setRememberMe: (value: boolean) => void;
  busy: boolean;
  error: string;
  onSubmit: () => void;
};

function EyeIcon({ hidden }: { hidden: boolean }) {
  return hidden ? (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
      <line x1="1" y1="1" x2="23" y2="23" />
    </svg>
  ) : (
    <svg viewBox="0 0 24 24" aria-hidden="true">
      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
      <circle cx="12" cy="12" r="3" />
    </svg>
  );
}
function TopologyScene() {
  return (
    <div className="fttw-topology-wrapper" aria-hidden="true">
      <svg
        className="fttw-topology-svg"
        viewBox="220 100 160 160"
        fill="none"
        xmlns="http://www.w3.org/2000/svg"
        shapeRendering="geometricPrecision"
      >
        <defs>
          <filter id="center-glow" x="-40%" y="-40%" width="180%" height="180%">
            <feGaussianBlur stdDeviation="8" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
          <linearGradient id="line-grad" x1="0%" y1="0%" x2="100%" y2="0%">
            <stop offset="0%" stopColor="#38bdf8" stopOpacity="0.3" />
            <stop offset="50%" stopColor="#60a5fa" stopOpacity="0.68" />
            <stop offset="100%" stopColor="#38bdf8" stopOpacity="0.3" />
          </linearGradient>
        </defs>

        <g className="fttw-signal-arcs" transform="translate(300, 180)">
          <path d="M -22 -22 A 31 31 0 0 0 -22 22" className="arc arc-1" />
          <path d="M 22 -22 A 31 31 0 0 1 22 22" className="arc arc-1" />
          <path d="M -34 -34 A 48 48 0 0 0 -34 34" className="arc arc-2" />
          <path d="M 34 -34 A 48 48 0 0 1 34 34" className="arc arc-2" />
          <path d="M -46 -46 A 65 65 0 0 0 -46 46" className="arc arc-3" />
          <path d="M 46 -46 A 65 65 0 0 1 46 46" className="arc arc-3" />
        </g>

        <g className="fttw-nodes">
          <g className="fttw-hub-node" transform="translate(300,180)" filter="url(#center-glow)">
            <circle r="18" className="fttw-hub-ring" />
            <circle r="8" className="fttw-hub-dot" />
          </g>
        </g>
      </svg>
    </div>
  );
}

export function LoginPage({
  username,
  password,
  rememberMe,
  setUsername,
  setPassword,
  setRememberMe,
  busy,
  error,
  onSubmit,
}: LoginPageProps) {
  const [showPassword, setShowPassword] = useState(false);
  const usernameInputRef = useRef<HTMLInputElement | null>(null);
  const passwordInputRef = useRef<HTMLInputElement | null>(null);
  const credentialError = /wrong username or password|invalid credentials/i.test(error);

  const syncBrowserCredentials = useCallback(() => {
    const domUsername = usernameInputRef.current?.value ?? "";
    const domPassword = passwordInputRef.current?.value ?? "";
    if (domUsername !== username) setUsername(domUsername);
    if (domPassword !== password) setPassword(domPassword);
  }, [password, setPassword, setUsername, username]);

  useEffect(() => {
    syncBrowserCredentials();
    const timer = window.setInterval(syncBrowserCredentials, 250);
    window.addEventListener("focus", syncBrowserCredentials);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("focus", syncBrowserCredentials);
    };
  }, [syncBrowserCredentials]);

  const handleSubmit = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    const domUsername = usernameInputRef.current?.value ?? username;
    const domPassword = passwordInputRef.current?.value ?? password;
    if (domUsername !== username) setUsername(domUsername);
    if (domPassword !== password) setPassword(domPassword);
    if (!busy && domUsername.trim() && domPassword) {
      onSubmit();
    }
  };

  return (
    <main className="fttw-login-root">
      <img
        className="fttw-login-corner-logo"
        src="/branding/logo.png"
        alt="Sudani"
      />
      <div className="fttw-bg-mesh" aria-hidden="true" />
      <div className="fttw-bg-glow-right" aria-hidden="true" />
      <div className="fttw-bg-glow-center" aria-hidden="true" />

      <svg className="fttw-bg-arcs" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1000 1000" fill="none" aria-hidden="true">
        <circle cx="850" cy="350" r="450" stroke="url(#arc-gradient-1)" strokeWidth="1.5" strokeOpacity="0.4" />
        <circle cx="850" cy="350" r="580" stroke="url(#arc-gradient-2)" strokeWidth="1" strokeOpacity="0.25" />
        <circle cx="850" cy="350" r="700" stroke="url(#arc-gradient-2)" strokeWidth="0.8" strokeOpacity="0.15" />
        <defs>
          <linearGradient id="arc-gradient-1" x1="400" y1="0" x2="1000" y2="800" gradientUnits="userSpaceOnUse">
            <stop stopColor="#186ade" stopOpacity="0.8" />
            <stop offset="1" stopColor="#0052ff" stopOpacity="0.05" />
          </linearGradient>
          <linearGradient id="arc-gradient-2" x1="200" y1="0" x2="1000" y2="1000" gradientUnits="userSpaceOnUse">
            <stop stopColor="#38bdf8" stopOpacity="0.5" />
            <stop offset="1" stopColor="#0284c7" stopOpacity="0" />
          </linearGradient>
        </defs>
      </svg>

      <section className="fttw-login-container" aria-label="FTTW Network Management System secure login">
        <div className="fttw-branding-section">
          <header className="fttw-brand-header">
            <h1 className="fttw-brand-title">FTTW Network<br />Management System</h1>
            <p className="fttw-brand-subtitle">UNIFIED OPERATIONS MANAGEMENT AND CONTROL PLATFORM</p>
          </header>
          <TopologyScene />
        </div>

        <div className="fttw-card-container">
          <div className="fttw-login-card">
            <div className="fttw-card-header">
              <div className="fttw-shield-badge" aria-hidden="true">
                <svg width="24" height="24" viewBox="0 0 24 24" fill="none">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" stroke="#0052FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  <path d="M9 12l2 2 4-4" stroke="#0052FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>
              </div>

              <div className="fttw-secure-tag">
                <span className="fttw-line" />
                <span className="fttw-tag-text">SECURE ACCESS</span>
                <span className="fttw-line" />
              </div>

              <h2 className="fttw-welcome-title">WELCOME BACK</h2>
              <div className="fttw-accent-pill" />
            </div>

            <form onSubmit={handleSubmit} className="fttw-login-form" noValidate>
              <div className="fttw-field-group">
                <label htmlFor="fttw-username" className="fttw-label">Username</label>
                <div className="fttw-input-wrapper">
                  <span className="fttw-input-icon" aria-hidden="true">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2" />
                      <circle cx="12" cy="7" r="4" />
                    </svg>
                  </span>
                  <Input
                    unstyled
                    ref={usernameInputRef}
                    id="fttw-username"
                    type="text"
                    value={username}
                    onChange={(event) => setUsername(event.target.value)}
                    placeholder="Enter your username"
                    className="fttw-input"
                    autoComplete="username"
                    spellCheck={false}
                    disabled={busy}
                  />
                </div>
              </div>

              <div className="fttw-field-group">
                <label htmlFor="fttw-password" className="fttw-label">Password</label>
                <div className={`fttw-input-wrapper${credentialError ? " fttw-input-error-state" : ""}`}>
                  <span className="fttw-input-icon" aria-hidden="true">
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
                      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
                    </svg>
                  </span>
                  <Input
                    unstyled
                    ref={passwordInputRef}
                    id="fttw-password"
                    type={showPassword ? "text" : "password"}
                    value={password}
                    onChange={(event) => setPassword(event.target.value)}
                    placeholder="Enter your password"
                    className="fttw-input fttw-input-pass"
                    autoComplete="current-password"
                    disabled={busy}
                    aria-invalid={credentialError || undefined}
                    aria-describedby={error ? "fttw-login-error" : undefined}
                  />
                  <Button
                    unstyled
                    type="button"
                    onClick={() => setShowPassword((value) => !value)}
                    className="fttw-password-toggle"
                    aria-label={showPassword ? "Hide password" : "Show password"}
                    disabled={busy}
                  >
                    <EyeIcon hidden={showPassword} />
                  </Button>
                </div>
              </div>

              <div
                id="fttw-login-error"
                className={`fttw-inline-error${error ? " is-visible" : ""}`}
                role={error ? "alert" : undefined}
                aria-live="polite"
              >
                {error && (
                  <>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
                      <circle cx="12" cy="12" r="10" />
                      <line x1="12" y1="8" x2="12" y2="12" />
                      <line x1="12" y1="16" x2="12.01" y2="16" />
                    </svg>
                    <span>{error}</span>
                  </>
                )}
              </div>

              <div className="fttw-remember-row">
                <label className="fttw-checkbox-label">
                  <Checkbox
                    unstyled
                    checked={rememberMe}
                    onChange={(event) => setRememberMe(event.target.checked)}
                    className="fttw-checkbox-input"
                    disabled={busy}
                  />
                  <span className="fttw-custom-checkbox" aria-hidden="true">
                    <svg width="12" height="10" viewBox="0 0 12 10" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <polyline points="1.5 5 4.5 8 10.5 1.5" />
                    </svg>
                  </span>
                  <span className="fttw-remember-text">Remember me</span>
                </label>
              </div>

              <Button
                unstyled
                type="submit"
                disabled={busy || !username.trim() || !password}
                className={`fttw-submit-btn${busy ? " fttw-btn-loading" : ""}`}
              >
                {busy ? (
                  <>
                    <span className="fttw-spinner" aria-hidden="true" />
                    <span>Signing in...</span>
                  </>
                ) : (
                  <>
                    <span>Sign in</span>
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="fttw-btn-arrow" aria-hidden="true">
                      <line x1="5" y1="12" x2="19" y2="12" />
                      <polyline points="12 5 19 12 12 19" />
                    </svg>
                  </>
                )}
              </Button>
            </form>

            <div className="fttw-card-footer">
              <div className="fttw-footer-divider" aria-hidden="true">
                <span className="fttw-divider-line" />
                <div className="fttw-divider-shield">
                  <svg width="12" height="14" viewBox="0 0 24 24" fill="#CBD5E1">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="M9 12l2 2 4-4" stroke="#ffffff" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </div>
                <span className="fttw-divider-line" />
              </div>

              <div className="fttw-authorized-badge">
                <div className="fttw-badge-icon" aria-hidden="true">
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#0052FF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
                    <path d="M9 12l2 2 4-4" />
                  </svg>
                </div>
                <span className="fttw-badge-text">Authorized access only</span>
              </div>
            </div>
          </div>
        </div>
      </section>
    </main>
  );
}






