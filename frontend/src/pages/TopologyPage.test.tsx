import { fireEvent, render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { DialogProvider } from "../components/common/DialogSystem";
import { FeedbackProvider } from "../components/common/FeedbackSystem";
import type { City, Location, Network } from "../types";
import { TopologyPage } from "./TopologyPage";

const network: Network = { id: "n1", name: "North Network", code: "NORTH", status: "ACTIVE" };
const city: City = { id: "c1", network_id: "n1", name: "Metro", code: "MET", status: "ACTIVE", service_vlan_id: 120 };
const location: Location = { id: "l1", city_id: "c1", name: "Central POP", code: "POP-01", status: "ACTIVE", network_name: "North Network", city_name: "Metro" };

describe("TopologyPage location-based physical topology", () => {
  it("preserves Sector View and adds Location View without exposing downstream selectors", () => {
    render(<DialogProvider><FeedbackProvider><TopologyPage
      token="token"
      permissions={["topology.read", "device.read"]}
      sourceNetworks={[network]}
      networks={[network]}
      cities={[city]}
      locations={[location]}
      sectors={[]}
      groups={[]}
      topology={null}
      onLoad={vi.fn()}
      onLoadGroup={vi.fn()}
      onTestAccessibility={vi.fn()}
      onDeleteDevice={vi.fn(async () => true)}
    /></FeedbackProvider></DialogProvider>);

    expect(screen.getByRole("tab", { name: "Hierarchy Tree" })).toBeInTheDocument();
    expect(screen.getByRole("tab", { name: "Sector View" })).toBeInTheDocument();
    const locationTab = screen.getByRole("tab", { name: "Location View" });
    expect(locationTab).toBeInTheDocument();

    fireEvent.click(locationTab);
    const locationHeading = screen.getByRole("heading", { name: "Location View" });
    expect(locationHeading).toBeInTheDocument();
    expect(locationHeading).toHaveAttribute(
      "data-help",
      expect.stringContaining("Logical Sector objects are not rendered as physical nodes"),
    );
    expect(screen.queryByText(/Direct physical infrastructure only/)).not.toBeInTheDocument();
    expect(screen.getByText("Show Location Topology")).toBeInTheDocument();
    expect(screen.queryByText("C-VLAN")).not.toBeInTheDocument();
    expect(screen.queryByText(/^Sector$/)).not.toBeInTheDocument();
  });
});
