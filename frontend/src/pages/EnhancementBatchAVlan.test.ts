import { describe, expect, it } from "vitest";

import customerPageSource from "./CustomerPage.tsx?raw";
import devicePageSource from "./DevicePage.tsx?raw";
import deviceWorkspaceSource from "../features/devices/useDeviceWorkspace.ts?raw";

describe("enhancement batch A VLAN contract", () => {
  it("keeps customer S-VLAN and C-VLAN server-sortable", () => {
    expect(customerPageSource).toContain('SortHeader label="S-VLAN" sortKey="service_vlan_id"');
    expect(customerPageSource).toContain('SortHeader label="C-VLAN" sortKey="customer_vlan_id"');
  });

  it("exposes inventory VLAN columns, dependent filters, sorting and export state", () => {
    expect(devicePageSource).toContain('kind="service" value={props.inventoryServiceVlan}');
    expect(devicePageSource).toContain('kind="customer" value={props.inventoryCustomerVlan}');
    expect(devicePageSource).toContain('props.setInventoryServiceVlan(value); props.setInventoryCustomerVlan("")');
    expect(devicePageSource).toContain('props.setDeviceType(e.target.value); props.setInventoryCustomerVlan("")');
    expect(devicePageSource).toContain('SortHeader label="S-VLAN" sortKey="service_vlan_id"');
    expect(devicePageSource).toContain('SortHeader label="C-VLAN" sortKey="customer_vlan_id"');
    expect(devicePageSource).toContain('service_vlan_id:props.inventoryServiceVlan,customer_vlan_id:props.inventoryCustomerVlan');
    expect(devicePageSource).toContain('props.setInventoryServiceVlan("");props.setInventoryCustomerVlan("")');
  });

  it("sends both VLAN filters to the server and resets pagination when they change", () => {
    expect(deviceWorkspaceSource).toContain('params.set("service_vlan_id", inventoryServiceVlan)');
    expect(deviceWorkspaceSource).toContain('params.set("customer_vlan_id", inventoryCustomerVlan)');
    expect(deviceWorkspaceSource).toContain('deviceType, inventoryServiceVlan, inventoryCustomerVlan');
  });
});
