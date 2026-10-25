import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "../api/client";
import { useDialog } from "../components/common/DialogSystem";
import { useFeedback } from "../components/common/FeedbackSystem";
import { friendlyError } from "../utils/feedback";
import {
  buildDeviceAccessMenuItems,
  DEVICE_ACCESS_CHANGED_EVENT,
  fetchDeviceAccessCapabilities,
  notifyDeviceAccessChanged,
  type DeviceAccessCapabilities,
  type DeviceAccessMenuItem,
  type DeviceAccessTarget,
} from "../utils/deviceAccess";
import { openSecureWebGuiWindow, openWebSshWindow } from "../utils/remoteAccess";
import { openWebTelnetWindow } from "../utils/telnetAccess";

type SSHRemoteAccessStatus = {
  ssh_enabled: boolean;
  ssh_host_key_fingerprint: string | null;
  ready: boolean;
};

type SSHHostKeyAction = {
  action: "DISCOVER_HOST_KEY" | "TRUST_HOST_KEY";
  device_id: string;
  template_id: string;
  template_name: string;
  fingerprint: string;
  key_type: string;
  port: number;
  compatibility_profile: string;
  pinned_fingerprint: string | null;
  trust_state: "NEW" | "MATCH" | "MISMATCH";
};

export function useDeviceAccessActions({
  token,
  permissions,
}: {
  token: string;
  permissions: string[];
}) {
  const dialog = useDialog();
  const feedback = useFeedback();
  const hasAnyRemotePermission = permissions.some((code) =>
    [
      "device.remote_access.web",
      "device.remote_access.ssh",
      "device.remote_access.telnet",
    ].includes(code),
  );

  const cacheRef = useRef<Record<string, DeviceAccessCapabilities>>({});
  const inFlightRef = useRef<Map<string, Promise<DeviceAccessCapabilities>>>(new Map());
  const [revision, setRevision] = useState(0);
  const [loadingIds, setLoadingIds] = useState<Set<string>>(new Set());

  const publish = useCallback((deviceId: string, value: DeviceAccessCapabilities) => {
    cacheRef.current = { ...cacheRef.current, [deviceId]: value };
    setRevision((current) => current + 1);
  }, []);

  const setLoading = useCallback((deviceId: string, loading: boolean) => {
    setLoadingIds((current) => {
      const next = new Set(current);
      if (loading) next.add(deviceId);
      else next.delete(deviceId);
      return next;
    });
  }, []);

  const loadCapabilities = useCallback(async (
    deviceId: string,
    force = false,
  ): Promise<DeviceAccessCapabilities | undefined> => {
    if (!hasAnyRemotePermission) return undefined;
    if (!force && cacheRef.current[deviceId]) return cacheRef.current[deviceId];

    const existing = inFlightRef.current.get(deviceId);
    if (existing) return existing;

    setLoading(deviceId, true);
    const request = fetchDeviceAccessCapabilities(token, deviceId);
    inFlightRef.current.set(deviceId, request);
    try {
      const value = await request;
      publish(deviceId, value);
      return value;
    } finally {
      inFlightRef.current.delete(deviceId);
      setLoading(deviceId, false);
    }
  }, [hasAnyRemotePermission, publish, setLoading, token]);

  useEffect(() => {
    const onAccessChanged = (event: Event) => {
      const deviceId = (event as CustomEvent<{ deviceId?: string }>).detail?.deviceId;
      if (!deviceId || !cacheRef.current[deviceId]) return;
      void loadCapabilities(deviceId, true).catch(() => undefined);
    };
    window.addEventListener(DEVICE_ACCESS_CHANGED_EVENT, onAccessChanged);
    return () => window.removeEventListener(DEVICE_ACCESS_CHANGED_EVENT, onAccessChanged);
  }, [loadCapabilities]);

  const capabilitiesFor = useCallback((deviceId: string) => {
    void revision;
    return cacheRef.current[deviceId];
  }, [revision]);

  const isLoading = useCallback((deviceId: string) => loadingIds.has(deviceId), [loadingIds]);

  const prefetch = useCallback(async (deviceId: string) => {
    try {
      await loadCapabilities(deviceId, false);
    } catch {
      // Hover/context prefetch is intentionally silent. Launch paths report errors.
    }
  }, [loadCapabilities]);

  const ensureSshHostTrust = useCallback(async (device: DeviceAccessTarget): Promise<boolean> => {
    const status = await apiFetch<SSHRemoteAccessStatus>(
      `/devices/${device.id}/remote-access`,
      {},
      token,
    );
    if (status.ready) return true;

    const discovery = await apiFetch<SSHHostKeyAction>(
      `/devices/${device.id}/remote-access/ssh-sessions`,
      {
        method: "POST",
        body: JSON.stringify({ action: "DISCOVER_HOST_KEY" }),
      },
      token,
    );

    if (discovery.trust_state === "MATCH") {
      const trusted = await apiFetch<SSHHostKeyAction>(
        `/devices/${device.id}/remote-access/ssh-sessions`,
        {
          method: "POST",
          body: JSON.stringify({
            action: "TRUST_HOST_KEY",
            expected_fingerprint: discovery.fingerprint,
            replace_existing: false,
          }),
        },
        token,
      );
      if (trusted.trust_state !== "MATCH") {
        throw new Error("SSH host key was not saved as trusted.");
      }
      feedback.success("SSH host key verified and Web SSH enabled for this device.");
      notifyDeviceAccessChanged(device.id);
      await loadCapabilities(device.id, true);
      return true;
    }

    const replacing = discovery.trust_state === "MISMATCH";
    const message = replacing
      ? `SSH HOST KEY CHANGED for ${device.display_name}.\n\nTrusted fingerprint:\n${discovery.pinned_fingerprint || "Not available"}\n\nCurrently observed fingerprint:\n${discovery.fingerprint}\n\nKey type: ${discovery.key_type}\nPort: ${discovery.port}\n\nA changed host key can indicate device replacement, SSH re-keying, or an impersonation attempt. Replace the trusted key only after independently verifying this fingerprint.`
      : `FTTW is connecting to ${device.display_name} by SSH for the first time.\n\nObserved fingerprint:\n${discovery.fingerprint}\n\nKey type: ${discovery.key_type}\nPort: ${discovery.port}\nAccess Template: ${discovery.template_name}\n\nTrust and save this device-specific SSH host key?`;

    const approved = await dialog.confirm({ message });
    if (!approved) return false;

    const trusted = await apiFetch<SSHHostKeyAction>(
      `/devices/${device.id}/remote-access/ssh-sessions`,
      {
        method: "POST",
        body: JSON.stringify({
          action: "TRUST_HOST_KEY",
          expected_fingerprint: discovery.fingerprint,
          replace_existing: replacing,
        }),
      },
      token,
    );
    if (trusted.trust_state !== "MATCH") {
      throw new Error("SSH host key was not saved as trusted.");
    }
    feedback.success(replacing ? "Trusted SSH host key replaced." : "SSH host key trusted and saved.");
    notifyDeviceAccessChanged(device.id);
    await loadCapabilities(device.id, true);
    return true;
  }, [dialog, feedback, loadCapabilities, token]);

  const verifySshHostKey = useCallback((device: DeviceAccessTarget) => {
    void (async () => {
      try {
        if (await ensureSshHostTrust(device)) {
          feedback.success("SSH host-key trust is ready for this device.");
        }
      } catch (error) {
        feedback.error(friendlyError(error, "Unable to verify the SSH host key."));
      }
    })();
  }, [ensureSshHostTrust, feedback]);

  const launchSecureWeb = useCallback((device: DeviceAccessTarget) => {
    const current = cacheRef.current[device.id];
    if (!current?.secure_web.available) return;
    void openSecureWebGuiWindow(token, device.id, device.display_name)
      .catch((error) => feedback.error(friendlyError(error, "Unable to start Secure Web GUI.")));
  }, [feedback, token]);

  const openSecureWebIfAvailable = useCallback((device: DeviceAccessTarget) => {
    const current = cacheRef.current[device.id];
    if (!current) {
      void prefetch(device.id);
      return false;
    }
    if (!current.secure_web.available) return false;
    launchSecureWeb(device);
    return true;
  }, [launchSecureWeb, prefetch]);

  const launchSsh = useCallback((device: DeviceAccessTarget) => {
    const current = cacheRef.current[device.id];
    if (!current?.ssh.available) return;

    if (current.ssh.ready) {
      void openWebSshWindow(token, device.id, device.display_name)
        .catch((error) => feedback.error(friendlyError(error, "Unable to start Web SSH.")));
      return;
    }

    void (async () => {
      try {
        if (!await ensureSshHostTrust(device)) return;
        await openWebSshWindow(token, device.id, device.display_name);
      } catch (error) {
        feedback.error(friendlyError(error, "Unable to start Web SSH."));
      }
    })();
  }, [ensureSshHostTrust, feedback, token]);

  const launchTelnet = useCallback((device: DeviceAccessTarget) => {
    const current = cacheRef.current[device.id];
    if (!current?.telnet.available) return;
    void (async () => {
      const approved = await dialog.confirm({
        message: `Start a legacy Telnet session to ${device.display_name}?\n\nTelnet is an insecure plaintext transport. Credentials and device traffic are not protected by transport encryption.`,
      });
      if (!approved) return;
      try {
        await openWebTelnetWindow(token, device.id, device.display_name);
      } catch (error) {
        feedback.error(friendlyError(error, "Unable to start Telnet."));
      }
    })();
  }, [dialog, feedback, token]);

  const menuItems = useCallback((device: DeviceAccessTarget): DeviceAccessMenuItem[] => {
    if (!hasAnyRemotePermission) return [];
    const capabilities = cacheRef.current[device.id];
    return buildDeviceAccessMenuItems({
      capabilities,
      loading: !capabilities || loadingIds.has(device.id),
      onSecureWeb: () => launchSecureWeb(device),
      onSsh: () => launchSsh(device),
      onTelnet: () => launchTelnet(device),
    });
  }, [hasAnyRemotePermission, launchSecureWeb, launchSsh, launchTelnet, loadingIds, revision]);

  return {
    hasAnyRemotePermission,
    loadCapabilities,
    prefetch,
    capabilitiesFor,
    isLoading,
    menuItems,
    launchSecureWeb,
    openSecureWebIfAvailable,
    launchSsh,
    launchTelnet,
    verifySshHostKey,
  };
}