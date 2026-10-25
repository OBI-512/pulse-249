import { apiFetch } from "../../api/client";
import { webGuiGatewayOrigin } from "../../utils/remoteAccess";


type WebRemoteLaunch = {
  session_id: string;
  ticket: string;
  expires_at: string;
};

type WebGuiReadyMessage = {
  type: "fttw-web-gui-ready";
  channel: string;
};

/**
 * Open an authenticated Secure GUI using one explicitly selected wizard draft.
 * The one-time launch ticket stays in memory and the draft template ID is bound
 * server-side to the remote-access session; credentials never reach the browser.
 */
export async function openWebTemplateWizardPreview(
  token: string,
  templateId: string,
  deviceId: string,
  deviceName: string,
): Promise<string> {
  const channel = crypto.randomUUID();
  const gatewayOrigin = webGuiGatewayOrigin();
  const launchUrl = new URL("/web/launch", gatewayOrigin);
  launchUrl.searchParams.set("channel", channel);
  launchUrl.searchParams.set("device", `${deviceName} — template preview`);
  launchUrl.searchParams.set("opener_origin", window.location.origin);
  const popup = window.open(launchUrl.toString(), "_blank");
  if (!popup) throw new Error("The browser blocked the Secure GUI preview tab. Allow pop-ups for FTTW and try again.");

  let readyResolve: (() => void) | null = null;
  let readyReject: ((error: Error) => void) | null = null;
  const ready = new Promise<void>((resolve, reject) => {
    readyResolve = resolve;
    readyReject = reject;
  });
  const onMessage = (event: MessageEvent<WebGuiReadyMessage>) => {
    if (event.origin !== gatewayOrigin || event.source !== popup) return;
    if (event.data?.type !== "fttw-web-gui-ready" || event.data.channel !== channel) return;
    readyResolve?.();
  };
  window.addEventListener("message", onMessage);
  const timeout = window.setTimeout(
    () => readyReject?.(new Error("The Secure GUI preview gateway did not become ready.")),
    10000,
  );

  try {
    await ready;
    if (popup.closed) throw new Error("The Secure GUI preview tab was closed before the session started.");
    const launch = await apiFetch<WebRemoteLaunch>(
      `/access-templates/web-wizard/${templateId}/preview`,
      {
        method: "POST",
        body: JSON.stringify({ device_id: deviceId }),
      },
      token,
    );
    popup.postMessage({
      type: "fttw-web-gui-launch",
      channel,
      session_id: launch.session_id,
      ticket: launch.ticket,
      expires_at: launch.expires_at,
    }, gatewayOrigin);
    return launch.session_id;
  } catch (error) {
    try { popup.close(); } catch { /* best effort */ }
    throw error;
  } finally {
    window.clearTimeout(timeout);
    window.removeEventListener("message", onMessage);
  }
}
