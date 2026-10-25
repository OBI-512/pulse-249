import { Button } from "../../design-system/primitives";
export function AuthorizedUseNotice({ onAcknowledge }: { onAcknowledge: () => void }) {
  return (
    <main className="authorized-use-gate">
      <div className="authorized-use-atmosphere" aria-hidden="true" />
      <section
        className="authorized-use-card"
        role="dialog"
        aria-modal="true"
        aria-labelledby="authorized-use-title"
        aria-describedby="authorized-use-description"
      >
        <div className="authorized-use-brand-row">
          <img src="/branding/logo.png" alt="" aria-hidden="true" className="authorized-use-logo" />
          <div>
            <div className="eyebrow">SECURE ACCESS</div>
            <div className="authorized-use-brand-copy">FTTW Network Management System</div>
          </div>
        </div>

        <div className="authorized-use-heading">
          <span className="authorized-use-lock" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="5" y="10" width="14" height="10" rx="2" />
              <path d="M8 10V7a4 4 0 0 1 8 0v3" />
            </svg>
          </span>
          <div>
            <h1 id="authorized-use-title">Authorized Use Notice</h1>
            <p>Proprietary network management platform</p>
          </div>
        </div>

        <div id="authorized-use-description" className="authorized-use-copy">
          <p>
            This system is intended solely for authorized personnel and approved business use. Access may allow you to view,
            configure, and manage network infrastructure, connected devices, operational data, and administrative functions.
          </p>

          <div className="authorized-use-policy-box">
            <strong>By continuing, you confirm that:</strong>
            <ul>
              <li>you are authorized to access and use this system;</li>
              <li>you will operate only within your approved responsibilities and permissions; and</li>
              <li>you understand that activity on this system may be monitored, logged, and audited.</li>
            </ul>
          </div>

          <p className="authorized-use-warning">
            Unauthorized access or use is prohibited. If you are not authorized to access this system, do not continue.
          </p>
        </div>

        <Button unstyled type="button" className="authorized-use-continue" autoFocus onClick={onAcknowledge}>
          <span>I ACKNOWLEDGE AND CONTINUE</span>
          <svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M5 12h14" />
            <path d="m13 6 6 6-6 6" />
          </svg>
        </Button>
      </section>
    </main>
  );
}
