import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { DiscoveryPage } from "./DiscoveryPage";

vi.mock("../design-system/data/TableExport", () => ({ TableExportButton: () => null }));

describe("DiscoveryPage management port fields", () => {
  it("shows independent optional HTTP/HTTPS inputs with protocol defaults and limits", () => {
    const setHttpPort = vi.fn();
    const setHttpsPort = vi.fn();
    render(<DiscoveryPage
      token="token"
      permissions={["discovery.run"]}
      busy={false}
      methods={["HTTP", "HTTPS"]}
      methodOptions={["HTTP", "HTTPS"]}
      setMethods={vi.fn()}
      ip="192.0.2.10"
      setIp={vi.fn()}
      timeout="2"
      setTimeoutValue={vi.fn()}
      httpPort=""
      setHttpPort={setHttpPort}
      httpsPort=""
      setHttpsPort={setHttpsPort}
      onRun={vi.fn()}
      batchIps=""
      setBatchIps={vi.fn()}
      batchCidrs=""
      setBatchCidrs={vi.fn()}
      concurrency="25"
      setConcurrency={vi.fn()}
      maxTargets="1000"
      setMaxTargets={vi.fn()}
      onBatch={vi.fn()}
      results={[]}
      selectedBatchJob={null}
      jobs={[]}
      jobSearch=""
      setJobSearch={vi.fn()}
      jobStatus=""
      setJobStatus={vi.fn()}
      jobScopeType=""
      setJobScopeType={vi.fn()}
      jobSort={{ key: "created_at", direction: "desc" }}
      setJobSort={vi.fn()}
      jobPage={1}
      jobPageSize={50}
      jobTotal={0}
      setJobPage={vi.fn()}
      setJobPageSize={vi.fn()}
    />);

    const http = screen.getByLabelText("HTTP port (optional)");
    const https = screen.getByLabelText("HTTPS port (optional)");
    expect(http).toHaveAttribute("min", "1");
    expect(http).toHaveAttribute("max", "65535");
    expect(http).toHaveAttribute("placeholder", "Default: 80");
    expect(https).toHaveAttribute("min", "1");
    expect(https).toHaveAttribute("max", "65535");
    expect(https).toHaveAttribute("placeholder", "Default: 443");

    fireEvent.change(http, { target: { value: "8080" } });
    fireEvent.change(https, { target: { value: "8443" } });
    expect(setHttpPort).toHaveBeenCalledWith("8080");
    expect(setHttpsPort).toHaveBeenCalledWith("8443");
  });
});
