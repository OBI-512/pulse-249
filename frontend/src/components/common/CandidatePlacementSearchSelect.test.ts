import { describe, expect, it } from "vitest";

import { placementFromAssignmentRow } from "./CandidatePlacementSearchSelect";

describe("candidate placement assignment mapping", () => {
  it("never fabricates a logical sector for a location option", () => {
    const placement = placementFromAssignmentRow({
      id: "location-1",
      label: "Lab location",
      network_id: "network-1",
      network_name: "Lab network",
      city_id: "city-1",
      city_name: "Lab city",
      location_id: "location-1",
      location_name: "Lab location",
    }, "locations");

    expect(placement.location_id).toBe("location-1");
    expect(placement.sector_id).toBeNull();
    expect(placement.sector_name).toBeNull();
    expect(placement.sector_role).toBeNull();
  });

  it("preserves the logical sector only for logical-sector options", () => {
    const placement = placementFromAssignmentRow({
      id: "sector-1",
      label: "Sector 1",
      network_id: "network-1",
      network_name: "Lab network",
      city_id: "city-1",
      city_name: "Lab city",
      location_id: "location-1",
      location_name: "Lab location",
      logical_sector_id: "sector-1",
      logical_sector_name: "Sector 1",
      sector_role: "CUSTOMER_ACCESS",
    }, "logical-sectors");

    expect(placement.location_id).toBe("location-1");
    expect(placement.sector_id).toBe("sector-1");
    expect(placement.sector_name).toBe("Sector 1");
    expect(placement.sector_role).toBe("CUSTOMER_ACCESS");
  });
});
