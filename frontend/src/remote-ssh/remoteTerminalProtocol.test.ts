import { describe, expect, it } from "vitest";
import terminalSource from "./main.ts?raw";
import shellSource from "../../remote-ssh.html?raw";


describe("shared SSH/Telnet terminal presentation", () => {
  it("selects the terminal protocol from the launch URL and keeps SSH as the default", () => {
    expect(terminalSource).toContain('params.get("protocol")');
    expect(terminalSource).toContain('=== "TELNET" ? "TELNET" : "SSH"');
    expect(terminalSource).toContain('protocol === "TELNET" ? "/ws/telnet" : "/ws/ssh"');
  });

  it("labels Telnet as legacy/insecure without changing SSH host-key behavior", () => {
    expect(terminalSource).toContain("Legacy Telnet — insecure");
    expect(terminalSource).toContain("TELNET_ACCESS_DISABLED");
    expect(terminalSource).toContain("TELNET_LOGIN_FAILED");
    expect(terminalSource).toContain("SSH_HOST_KEY_MISMATCH");
    expect(terminalSource).toContain("LEGACY_SSH_RSA_DH1_CBC");
  });

  it("uses protocol-neutral static shell text before the runtime protocol is known", () => {
    expect(shellSource).toContain("FTTW Remote Terminal");
    expect(shellSource).toContain('aria-label="Remote terminal"');
    expect(shellSource).toContain("Waiting for terminal session…");
    expect(shellSource).not.toContain("FTTW SSH Terminal");
  });
});
