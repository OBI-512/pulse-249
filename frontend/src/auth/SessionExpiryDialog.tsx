import { useEffect, useState } from "react";
import { DialogActions, DialogBackdrop, DialogCard, DialogHeader, DialogMessage } from "../design-system/composites/Dialog";
import { Button } from "../design-system/primitives";
import type { SessionExtensionOffer } from "./useSession";

function formatCountdown(seconds: number) {
  const safe = Math.max(0, seconds);
  const minutes = Math.floor(safe / 60);
  const remainder = safe % 60;
  return `${String(minutes).padStart(2, "0")}:${String(remainder).padStart(2, "0")}`;
}

function formatRenewal(minutes: number) {
  if (minutes % 60 === 0) {
    const hours = minutes / 60;
    return `${hours} hour${hours === 1 ? "" : "s"}`;
  }
  return `${minutes} minutes`;
}

export function SessionExpiryDialog({
  offer,
  busy,
  onExtend,
  onDecline,
}: {
  offer: SessionExtensionOffer | null;
  busy: boolean;
  onExtend: () => void;
  onDecline: () => void;
}) {
  const [secondsRemaining, setSecondsRemaining] = useState(offer?.secondsRemaining ?? 0);

  useEffect(() => {
    if (!offer) return;
    setSecondsRemaining(offer.secondsRemaining);
    const deadline = Date.now() + offer.secondsRemaining * 1000;
    const timer = window.setInterval(() => {
      setSecondsRemaining(Math.max(0, Math.ceil((deadline - Date.now()) / 1000)));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [offer?.expiresAt, offer?.secondsRemaining]);

  if (!offer) return null;

  return (
    <DialogBackdrop role="presentation">
      <DialogCard role="dialog" aria-modal="true" aria-labelledby="session-expiry-title">
        <DialogHeader eyebrow="SESSION SECURITY" title="Session about to expire" titleId="session-expiry-title" />
        <DialogMessage>
          Your session expires in <strong>{formatCountdown(secondsRemaining)}</strong>. Extend it for another {formatRenewal(offer.renewalMinutes)} to continue working.
        </DialogMessage>
        <DialogActions>
          <Button unstyled type="button" className="secondary" disabled={busy} onClick={onDecline}>Not now</Button>
          <Button unstyled type="button" disabled={busy || secondsRemaining <= 0} onClick={onExtend}>
            {busy ? "Extending..." : "Extend session"}
          </Button>
        </DialogActions>
      </DialogCard>
    </DialogBackdrop>
  );
}
