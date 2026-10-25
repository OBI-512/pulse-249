import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, apiFetch } from "../api/client";
import type { AuthUser } from "../types";
import { collectClientSessionMetadata } from "../utils/sessionTelemetry";

const SESSION_TOKEN_KEY = "fttw_session_token";
const AUTHORIZED_USE_ACK_KEY = "fttw_authorized_use_ack_v1";

type SessionStatus = {
  session_id: string;
  expires_at: string;
  seconds_remaining: number;
  idle_seconds: number;
  idle_timeout_seconds: number;
  extension_window_seconds: number;
  extension_eligible: boolean;
  renewal_minutes: number;
  must_change_password: boolean;
  password_change_reason: string | null;
};

export type SessionExtensionOffer = {
  expiresAt: string;
  secondsRemaining: number;
  renewalMinutes: number;
};

type SessionExtendResponse = {
  session_id: string;
  expires_at: string;
  seconds_remaining: number;
  renewal_minutes: number;
};

type UseSessionOptions = {
  onLoginStart?: () => void;
  onLoginSuccess?: () => void;
  onSignedOut?: () => void;
};

export function useSession(options: UseSessionOptions = {}) {
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const [token, setToken] = useState(
    () => localStorage.getItem(SESSION_TOKEN_KEY) || sessionStorage.getItem(SESSION_TOKEN_KEY) || "",
  );
  const [currentUser, setCurrentUser] = useState<AuthUser | null>(null);
  const [authorizedUseAcknowledgedFor, setAuthorizedUseAcknowledgedFor] = useState(
    () => sessionStorage.getItem(AUTHORIZED_USE_ACK_KEY) || "",
  );
  const [loginUsername, setLoginUsernameState] = useState("");
  const [loginPassword, setLoginPasswordState] = useState("");
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [loginRememberMe, setLoginRememberMe] = useState(() => Boolean(localStorage.getItem(SESSION_TOKEN_KEY)));
  const [sessionExtensionOffer, setSessionExtensionOffer] = useState<SessionExtensionOffer | null>(null);
  const [sessionExtensionBusy, setSessionExtensionBusy] = useState(false);
  const declinedExpiryRef = useRef("");

  const currentUserRef = useRef<AuthUser | null>(currentUser);
  currentUserRef.current = currentUser;
  const initialTokenRef = useRef(token);

  const saveToken = useCallback((value: string, persist = false) => {
    const normalized = value.trim();
    setToken(normalized);
    if (!normalized) {
      localStorage.removeItem(SESSION_TOKEN_KEY);
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
      sessionStorage.removeItem(AUTHORIZED_USE_ACK_KEY);
      setAuthorizedUseAcknowledgedFor("");
      return;
    }
    if (persist) {
      localStorage.setItem(SESSION_TOKEN_KEY, normalized);
      sessionStorage.removeItem(SESSION_TOKEN_KEY);
    } else {
      sessionStorage.setItem(SESSION_TOKEN_KEY, normalized);
      localStorage.removeItem(SESSION_TOKEN_KEY);
    }
  }, []);

  const clearLocalSession = useCallback(() => {
    saveToken("");
    setCurrentUser(null);
    setSessionExtensionOffer(null);
    setSessionExtensionBusy(false);
    declinedExpiryRef.current = "";
    optionsRef.current.onSignedOut?.();
  }, [saveToken]);

  const forceLocalSignOut = useCallback((reason = "Your session has ended. Sign in again to continue.") => {
    clearLocalSession();
    setLoginPasswordState("");
    setLoginError(reason);
  }, [clearLocalSession]);

  const loadCurrentUser = useCallback(async (sessionToken: string) => {
    const user = await apiFetch<AuthUser>("/auth/me", {}, sessionToken);
    if (user.must_change_password) {
      sessionStorage.removeItem(AUTHORIZED_USE_ACK_KEY);
      setAuthorizedUseAcknowledgedFor("");
    }
    setCurrentUser(user);
    return user;
  }, []);

  const setLoginUsername = useCallback((value: string) => {
    setLoginUsernameState(value);
    setLoginError("");
  }, []);

  const setLoginPassword = useCallback((value: string) => {
    setLoginPasswordState(value);
    setLoginError("");
  }, []);

  const login = useCallback(async () => {
    setLoginBusy(true);
    setLoginError("");
    optionsRef.current.onLoginStart?.();
    try {
      const result = await apiFetch<{ access_token: string; token_type: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify({ username: loginUsername, password: loginPassword }),
      });
      saveToken(result.access_token, loginRememberMe);
      await loadCurrentUser(result.access_token);
      setLoginPasswordState("");
      setLoginError("");
      optionsRef.current.onLoginSuccess?.();
    } catch (err) {
      saveToken("");
      setCurrentUser(null);
      if (err instanceof ApiError) {
        if (err.status === 401 || err.code === "INVALID_CREDENTIALS") {
          setLoginError("Wrong username or password.");
        } else if (err.status === 429 || err.code === "LOGIN_RATE_LIMITED") {
          setLoginError("Too many failed login attempts. Please try again later.");
        } else if (err.status === 0 || err.code === "NETWORK_REQUEST_FAILED") {
          setLoginError("Unable to reach the server. Check the connection and try again.");
        } else if (err.status >= 500) {
          setLoginError("The server is currently unavailable. Please try again shortly.");
        } else {
          setLoginError("Unable to sign in right now. Please try again.");
        }
      } else {
        setLoginError("Unable to sign in right now. Please try again.");
      }
    } finally {
      setLoginBusy(false);
    }
  }, [loadCurrentUser, loginPassword, loginRememberMe, loginUsername, saveToken]);

  const logout = useCallback(async () => {
    try {
      if (token) await apiFetch("/auth/logout", { method: "POST" }, token);
    } catch {
      // Local sign-out still completes if the server cannot be reached.
    }
    clearLocalSession();
  }, [clearLocalSession, token]);

  const extendCurrentSession = useCallback(async () => {
    if (!token || !sessionExtensionOffer || sessionExtensionBusy) return;
    setSessionExtensionBusy(true);
    try {
      // The explicit Extend click is itself human activity. Persist it before
      // asking the server to renew the absolute session deadline.
      await apiFetch("/auth/session/activity", { method: "POST" }, token);
      const renewed = await apiFetch<SessionExtendResponse>("/auth/session/extend", { method: "POST" }, token);
      declinedExpiryRef.current = "";
      setSessionExtensionOffer(null);
      if (renewed.seconds_remaining <= 0) {
        forceLocalSignOut("Your session has expired. Sign in again to continue.");
      }
    } catch (error) {
      if (error instanceof ApiError && error.status === 409) {
        setSessionExtensionOffer(null);
      }
      throw error;
    } finally {
      setSessionExtensionBusy(false);
    }
  }, [forceLocalSignOut, sessionExtensionBusy, sessionExtensionOffer, token]);

  const declineSessionExtension = useCallback(() => {
    if (sessionExtensionOffer) declinedExpiryRef.current = sessionExtensionOffer.expiresAt;
    setSessionExtensionOffer(null);
  }, [sessionExtensionOffer]);

  const completeRequiredPasswordChange = useCallback(async (newToken: string) => {
    const persist = Boolean(localStorage.getItem(SESSION_TOKEN_KEY));
    sessionStorage.removeItem(AUTHORIZED_USE_ACK_KEY);
    setAuthorizedUseAcknowledgedFor("");
    saveToken(newToken, persist);
    const refreshed = await loadCurrentUser(newToken);
    if (refreshed.must_change_password) {
      throw new Error("Password-change requirement was not cleared by the server.");
    }
  }, [loadCurrentUser, saveToken]);

  const acknowledgeAuthorizedUse = useCallback(() => {
    const user = currentUserRef.current;
    if (!user) return;
    sessionStorage.setItem(AUTHORIZED_USE_ACK_KEY, user.id);
    setAuthorizedUseAcknowledgedFor(user.id);
  }, []);

  useEffect(() => {
    const savedToken = initialTokenRef.current;
    if (!savedToken) return;
    void loadCurrentUser(savedToken).catch(() => {
      forceLocalSignOut("Your saved session is no longer valid. Sign in again to continue.");
    });
  }, [forceLocalSignOut, loadCurrentUser]);

  useEffect(() => {
    if (!token) return;
    let refreshInFlight = false;
    const refreshPermissions = () => {
      if (refreshInFlight) return;
      refreshInFlight = true;
      void loadCurrentUser(token)
        .catch(() => undefined)
        .finally(() => { refreshInFlight = false; });
    };
    window.addEventListener("fttw:permission-denied", refreshPermissions);
    return () => window.removeEventListener("fttw:permission-denied", refreshPermissions);
  }, [loadCurrentUser, token]);

  useEffect(() => {
    const handleInvalidSession = (event: Event) => {
      const detail = (event as CustomEvent<{ code?: string | null; message?: string }>).detail;
      const reason = detail?.code === "AUTHENTICATION_REQUIRED"
        ? "Your session has expired or was revoked. Sign in again to continue."
        : (detail?.message || "Your session is no longer valid. Sign in again to continue.");
      forceLocalSignOut(reason);
    };
    window.addEventListener("fttw:session-invalid", handleInvalidSession);
    return () => window.removeEventListener("fttw:session-invalid", handleInvalidSession);
  }, [forceLocalSignOut]);

  useEffect(() => {
    if (!token || !currentUser) return;
    let cancelled = false;
    let inFlight = false;
    let expiryTimer: number | undefined;

    const scheduleExpiry = (secondsRemaining: number) => {
      if (expiryTimer !== undefined) window.clearTimeout(expiryTimer);
      expiryTimer = window.setTimeout(() => {
        forceLocalSignOut("Your session has expired. Sign in again to continue.");
      }, Math.max(0, secondsRemaining * 1000 + 250));
    };

    const check = async () => {
      if (inFlight || cancelled) return;
      inFlight = true;
      try {
        const status = await apiFetch<SessionStatus>("/auth/session/status", {}, token);
        if (!cancelled) {
          scheduleExpiry(status.seconds_remaining);
          if (status.extension_eligible && declinedExpiryRef.current !== status.expires_at) {
            setSessionExtensionOffer({
              expiresAt: status.expires_at,
              secondsRemaining: status.seconds_remaining,
              renewalMinutes: status.renewal_minutes,
            });
          } else {
            setSessionExtensionOffer((current) => {
              if (!current || current.expiresAt !== status.expires_at) return current;
              if (!status.extension_eligible) return null;
              return { ...current, secondsRemaining: status.seconds_remaining, renewalMinutes: status.renewal_minutes };
            });
          }
          if (status.must_change_password && !currentUserRef.current?.must_change_password) {
            void loadCurrentUser(token).catch(() => undefined);
          }
        }
      } catch (error) {
        // Auth failures are handled centrally by apiFetch. Network failures do
        // not force logout because temporary backend loss is not session expiry.
        if (!(error instanceof ApiError) || error.status !== 401) void 0;
      } finally {
        inFlight = false;
      }
    };

    void check();
    const interval = window.setInterval(() => void check(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(interval);
      if (expiryTimer !== undefined) window.clearTimeout(expiryTimer);
    };
  }, [currentUser?.id, forceLocalSignOut, loadCurrentUser, token]);

  useEffect(() => {
    if (!token || !currentUser) return;
    let cancelled = false;
    void collectClientSessionMetadata()
      .then((metadata) => {
        if (!cancelled) {
          return apiFetch("/auth/session/client-metadata", { method: "POST", body: JSON.stringify(metadata) }, token);
        }
        return undefined;
      })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [currentUser?.id, token]);

  useEffect(() => {
    if (!token || !currentUser) return;
    let lastSent = 0;
    const reportHumanActivity = () => {
      if (document.visibilityState !== "visible") return;
      const now = Date.now();
      if (now - lastSent < 30000) return;
      lastSent = now;
      void apiFetch("/auth/session/activity", { method: "POST" }, token).catch(() => undefined);
    };
    const events: Array<keyof WindowEventMap> = ["pointerdown", "pointermove", "keydown", "wheel", "touchstart"];
    for (const eventName of events) window.addEventListener(eventName, reportHumanActivity, { passive: true });
    return () => {
      for (const eventName of events) window.removeEventListener(eventName, reportHumanActivity);
    };
  }, [currentUser?.id, token]);

  return {
    token,
    currentUser,
    authorizedUseAcknowledgedFor,
    loginUsername,
    loginPassword,
    loginRememberMe,
    loginBusy,
    loginError,
    sessionExtensionOffer,
    sessionExtensionBusy,
    setLoginUsername,
    setLoginPassword,
    setLoginRememberMe,
    login,
    logout,
    extendCurrentSession,
    declineSessionExtension,
    completeRequiredPasswordChange,
    acknowledgeAuthorizedUse,
    clearLocalSession,
  };
}
