import { useEffect } from "react";
import { Button } from "../../design-system/primitives";
import type { Device } from "../../types";
import { useDeviceAccessActions } from "../../hooks/useDeviceAccessActions";
import { WebTlsOnboardingPanel } from "./WebTlsOnboardingPanel";

export function DeviceAccessActions({
  token,
  device,
  permissions,
}: {
  token: string;
  device: Pick<Device, "id" | "display_name" | "management_ip" | "lifecycle_state">;
  permissions: string[];
}) {
  const access = useDeviceAccessActions({ token, permissions });

  useEffect(() => {
    if (!access.hasAnyRemotePermission) return;
    void access.loadCapabilities(device.id, true).catch(() => undefined);
  }, [access.hasAnyRemotePermission, access.loadCapabilities, device.id]);

  if (!access.hasAnyRemotePermission) return null;

  const capabilities = access.capabilitiesFor(device.id);
  const loading = access.isLoading(device.id);

  return <>
    <div className="panel-subsection">
      <h4>Remote access</h4>
      <p className="field-help">
        Launch methods are resolved from your permissions, the device's effective Access Templates,
        device-specific transport readiness, and installation-wide safety switches.
      </p>
      {!capabilities && loading && <div className="inline-status-message">Checking remote-access availability…</div>}
      {capabilities && <div className="button-row">
        {capabilities.secure_web.available && <Button unstyled className="secondary" onClick={() => access.launchSecureWeb(device)}>Secure GUI</Button>}
        {capabilities.ssh.available && capabilities.ssh.reason_code === "SSH_HOST_KEY_TRUST_REQUIRED" && <Button unstyled className="secondary" onClick={() => access.verifySshHostKey(device)}>Verify SSH host key</Button>}
        {capabilities.ssh.available && <Button
          unstyled
          className="secondary"
          disabled={!capabilities.ssh.ready && capabilities.ssh.reason_code !== "SSH_HOST_KEY_TRUST_REQUIRED"}
          onClick={() => access.launchSsh(device)}
        >{capabilities.ssh.ready || capabilities.ssh.reason_code === "SSH_HOST_KEY_TRUST_REQUIRED" ? "SSH Terminal" : "SSH Terminal (not ready)"}</Button>}
        {capabilities.telnet.available && <Button unstyled className="secondary" onClick={() => access.launchTelnet(device)}>Telnet Terminal</Button>}
      </div>}
      {capabilities
        && !capabilities.secure_web.available
        && !capabilities.ssh.available
        && !capabilities.telnet.available
        && <div className="field-help">No remote-access method is currently available for this device.</div>}
    </div>
    <WebTlsOnboardingPanel token={token} device={device} permissions={permissions} />
  </>;
}
