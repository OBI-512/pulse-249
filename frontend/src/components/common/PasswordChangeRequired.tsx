import { type FormEvent, useEffect, useMemo, useState } from "react";
import { ApiError, apiFetch } from "../../api/client";
import { Button, Input } from "../../design-system/primitives";

type PasswordChangeRequiredProps = {
  token: string;
  username: string;
  reason: string | null;
  onChanged: (newToken: string) => Promise<void> | void;
  onLogout: () => Promise<void> | void;
};

type LoginResponse = {
  access_token: string;
  token_type: string;
};

type PasswordPolicy = {
  minimum_length: number;
  require_complexity: boolean;
  history_count: number;
  minimum_edit_distance: number;
  maximum_age_days: number;
  expiry_warning_days: number;
};

function reasonCopy(reason: string | null) {
  if (reason === "PASSWORD_EXPIRED") {
    return {
      eyebrow: "PASSWORD EXPIRED",
      title: "Password Change Required",
      body: "Your password has expired. Create a new password before continuing to the network management system.",
    };
  }
  if (reason === "ADMIN_RESET") {
    return {
      eyebrow: "TEMPORARY PASSWORD",
      title: "Set Your New Password",
      body: "An administrator reset your password. Replace the temporary password before accessing the system.",
    };
  }
  return {
    eyebrow: "FIRST SIGN-IN",
    title: "Set Your New Password",
    body: "Your account is using a temporary password. Create your own password before accessing the system.",
  };
}

export function PasswordChangeRequired({ token, username, reason, onChanged, onLogout }: PasswordChangeRequiredProps) {
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [policy, setPolicy] = useState<PasswordPolicy>({
    minimum_length: 8,
    require_complexity: true,
    history_count: 5,
    minimum_edit_distance: 3,
    maximum_age_days: 0,
    expiry_warning_days: 14,
  });

  useEffect(() => {
    let cancelled = false;
    void apiFetch<PasswordPolicy>("/auth/password-policy", {}, token)
      .then((result) => { if (!cancelled) setPolicy(result); })
      .catch(() => { /* Safe baseline defaults remain effective in the UI. */ });
    return () => { cancelled = true; };
  }, [token]);

  const copy = reasonCopy(reason);
  const requirements = useMemo(() => {
    const items = [{ label: `At least ${policy.minimum_length} characters`, ok: newPassword.length >= policy.minimum_length }];
    if (policy.require_complexity) {
      items.push(
        { label: "One uppercase letter", ok: /[A-Z]/.test(newPassword) },
        { label: "One lowercase letter", ok: /[a-z]/.test(newPassword) },
        { label: "One number", ok: /[0-9]/.test(newPassword) },
        { label: "One symbol", ok: /[^A-Za-z0-9\s]/.test(newPassword) },
      );
    }
    return items;
  }, [newPassword, policy.minimum_length, policy.require_complexity]);

  const policyReady = requirements.every((item) => item.ok);
  const passwordsMatch = Boolean(confirmPassword) && newPassword === confirmPassword;

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setError("");

    if (!policyReady) {
      setError("The new password does not meet the required password policy.");
      return;
    }
    if (newPassword !== confirmPassword) {
      setError("New password and confirmation do not match.");
      return;
    }

    setBusy(true);
    try {
      const result = await apiFetch<LoginResponse>(
        "/auth/password/change-required",
        {
          method: "POST",
          body: JSON.stringify({ current_password: currentPassword, new_password: newPassword }),
        },
        token,
      );
      await onChanged(result.access_token);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.code === "CURRENT_PASSWORD_INVALID") {
          setError("The current or temporary password is incorrect.");
        } else if (err.code === "PASSWORD_REUSED" || err.code === "PASSWORD_HISTORY_REUSE") {
          setError("Choose a password that has not been used recently.");
        } else if (err.code === "PASSWORD_TOO_SIMILAR") {
          setError("The new password is too similar to the current password.");
        } else if (err.code === "PASSWORD_POLICY_VIOLATION") {
          setError(err.message || "The new password does not meet the password policy.");
        } else {
          setError(err.message || "Unable to change the password right now.");
        }
      } else {
        setError("Unable to change the password right now.");
      }
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="password-change-gate">
      <div className="password-change-atmosphere" aria-hidden="true" />
      <section className="password-change-card" aria-labelledby="password-change-title">
        <div className="password-change-brand-row">
          <img src="/branding/logo.png" alt="" aria-hidden="true" className="password-change-logo" />
          <div>
            <div className="eyebrow">SECURE ACCESS</div>
            <div className="password-change-brand-copy">FTTW Network Management System</div>
          </div>
        </div>

        <div className="password-change-heading">
          <span className="password-change-lock" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="5" y="10" width="14" height="10" rx="2" />
              <path d="M8 10V7a4 4 0 0 1 8 0v3" />
              <path d="M12 14v2" />
            </svg>
          </span>
          <div>
            <div className="password-change-reason">{copy.eyebrow}</div>
            <h1 id="password-change-title">{copy.title}</h1>
            <p>{copy.body}</p>
          </div>
        </div>

        <div className="password-change-account">Signed in as <strong>{username}</strong></div>

        <form className="password-change-form" onSubmit={submit}>
          <label>
            <span>Current / temporary password</span>
            <Input
              unstyled
              type="password"
              autoComplete="current-password"
              value={currentPassword}
              onChange={(event) => { setCurrentPassword(event.target.value); setError(""); }}
              disabled={busy}
              required
              autoFocus
            />
          </label>

          <label>
            <span>New password</span>
            <Input
              unstyled
              type="password"
              autoComplete="new-password"
              value={newPassword}
              onChange={(event) => { setNewPassword(event.target.value); setError(""); }}
              disabled={busy}
              required
            />
          </label>

          <label>
            <span>Confirm new password</span>
            <Input
              unstyled
              type="password"
              autoComplete="new-password"
              value={confirmPassword}
              onChange={(event) => { setConfirmPassword(event.target.value); setError(""); }}
              disabled={busy}
              required
            />
          </label>

          <div className="password-change-policy" aria-label="Password requirements">
            <strong>Password requirements</strong>
            <div className="password-change-policy-grid">
              {requirements.map((item) => (
                <span key={item.label} className={item.ok ? "met" : ""}>
                  <span aria-hidden="true">{item.ok ? "✓" : "•"}</span>
                  {item.label}
                </span>
              ))}
              <span className={passwordsMatch ? "met" : ""}>
                <span aria-hidden="true">{passwordsMatch ? "✓" : "•"}</span>
                Confirmation matches
              </span>
            </div>
            <small>
              {policy.history_count > 0 ? `The last ${policy.history_count} password(s) cannot be reused. ` : ""}
              {policy.minimum_edit_distance > 0 ? `The new password must differ from the current password by at least ${policy.minimum_edit_distance} edits.` : ""}
            </small>
          </div>

          {error && <div className="password-change-error" role="alert">{error}</div>}

          <Button unstyled type="submit" className="password-change-submit" disabled={busy || !currentPassword || !policyReady || !passwordsMatch}>
            {busy ? "UPDATING PASSWORD..." : "UPDATE PASSWORD AND CONTINUE"}
          </Button>
        </form>

        <Button unstyled type="button" className="password-change-logout" onClick={() => void onLogout()} disabled={busy}>
          Sign out
        </Button>
      </section>
    </main>
  );
}
